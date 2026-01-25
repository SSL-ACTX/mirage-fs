// src/url_media.rs
use crate::block_device::{BlockDevice, BLOCK_SIZE, ENCRYPTED_BLOCK_SIZE};
use crate::png_disk::PngDisk;
use crate::jpeg_disk::JpegDisk;
use crate::webp_disk::WebPDisk;
use std::collections::HashSet;
use std::io::{self, Error, ErrorKind, Read, Write};
use std::path::Path;
use std::time::Duration;
use log::{info, warn, debug};
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, RANGE};
use reqwest::redirect::Policy;
use reqwest::Url;
use tempfile::TempDir;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce
};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2
};

// ISO BMFF Constants
const ATOM_MDAT: [u8; 4] = *b"mdat";

// H.264 NAL Unit Constants
const NAL_PREFIX: [u8; 4] = [0x00, 0x00, 0x00, 0x01];
const NAL_FILLER_TYPE: u8 = 0x0C;
const NAL_OVERHEAD: usize = 5;
const NAL_PACKET_SIZE: usize = NAL_OVERHEAD + ENCRYPTED_BLOCK_SIZE;

const SALT_SIZE: usize = 16;
const MIRAGE_MAGIC: &[u8; 8] = b"MRG_AVC1";
const DEFAULT_MAX_DOWNLOAD_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB
const DEFAULT_READAHEAD_BYTES: usize = 512 * 1024; // 512 KiB

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MediaKind {
    Png,
    Jpeg,
    Webp,
    Mp4,
}

pub fn is_url(source: &str) -> bool {
    source.starts_with("http://") || source.starts_with("https://")
}

pub fn open_media_url(url: &str, password: &str) -> anyhow::Result<Box<dyn BlockDevice>> {
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(Policy::limited(10))
        .user_agent("MirageFS/1.4.0")
        .build()?;

    let resolved_url = resolve_media_url(&client, url, 8)?;
    let head_info = fetch_head_info(&client, &resolved_url);
    let kind = detect_media_kind(&head_info.final_url, head_info.content_type.as_deref())
        .ok_or_else(|| anyhow::anyhow!("Unsupported or unknown media type for URL: {}", url))?;

    match kind {
        MediaKind::Mp4 => {
            let reader = HttpRangeReader::new(
                client,
                url.to_string(),
                head_info.final_url,
                head_info.content_length,
            )?;
            let disk = UrlMp4Disk::new(reader, password)?;
            Ok(Box::new(ReadOnlyDevice::new(Box::new(disk), None)))
        }
        MediaKind::Png | MediaKind::Jpeg | MediaKind::Webp => {
            let temp_dir = tempfile::TempDir::new()?;
            let file_path = temp_dir.path().join("mirage_media");
            download_to_file(&client, &head_info.final_url, &file_path)?;

            let disk: Box<dyn BlockDevice> = match kind {
                MediaKind::Png => Box::new(PngDisk::new(file_path, password, false)?),
                MediaKind::Jpeg => Box::new(JpegDisk::new(file_path, password, false)?),
                MediaKind::Webp => Box::new(WebPDisk::new(file_path, password, false)?),
                MediaKind::Mp4 => unreachable!(),
            };

            Ok(Box::new(ReadOnlyDevice::new(disk, Some(temp_dir))))
        }
    }
}

struct HeadInfo {
    content_type: Option<String>,
    content_length: Option<u64>,
    final_url: String,
}

fn fetch_head_info(client: &Client, url: &str) -> HeadInfo {
    let mut content_type = None;
    let mut content_length = None;
    let mut final_url = url.to_string();

    if let Ok(res) = client.head(url).send() {
        final_url = res.url().to_string();
        if res.status().is_success() {
            content_type = res.headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            content_length = res.headers()
                .get(CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());
            return HeadInfo { content_type, content_length, final_url };
        }
    }

    if let Ok(res) = client.get(url).header(RANGE, "bytes=0-0").send() {
        final_url = res.url().to_string();
        if res.status().is_success() || res.status().as_u16() == 206 {
            content_type = res.headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            content_length = res.headers()
                .get(CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());
        }
    }

    HeadInfo { content_type, content_length, final_url }
}

fn detect_media_kind(url: &str, content_type: Option<&str>) -> Option<MediaKind> {
    if let Some(kind) = detect_media_kind_from_url(url) {
        return Some(kind);
    }

    if let Some(ct) = content_type {
        let ct = ct.to_ascii_lowercase();
        if ct.contains("image/png") { return Some(MediaKind::Png); }
        if ct.contains("image/jpeg") { return Some(MediaKind::Jpeg); }
        if ct.contains("image/jpg") { return Some(MediaKind::Jpeg); }
        if ct.contains("image/webp") { return Some(MediaKind::Webp); }
        if ct.contains("video/mp4") { return Some(MediaKind::Mp4); }
        if ct.contains("video/quicktime") { return Some(MediaKind::Mp4); }
    }
    None
}

fn detect_media_kind_from_url(url: &str) -> Option<MediaKind> {
    let url_no_query = url.split('?').next().unwrap_or(url);
    let name = url_no_query.rsplit('/').next().unwrap_or("");
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();

    match ext.as_str() {
        "png" => Some(MediaKind::Png),
        "jpg" | "jpeg" => Some(MediaKind::Jpeg),
        "webp" => Some(MediaKind::Webp),
        "mp4" | "m4v" | "mov" => Some(MediaKind::Mp4),
        _ => None,
    }
}

fn download_to_file(client: &Client, url: &str, path: &Path) -> anyhow::Result<()> {
    let resolved = resolve_media_url(client, url, 8)?;
    info!("Downloading remote media to local cache: {}", resolved);
    let mut resp = client.get(&resolved).send()?.error_for_status()?;
    let content_type = resp.headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase());
    let max_bytes = max_download_bytes();
    if let Some(len) = resp.headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
    {
        if len > max_bytes {
            anyhow::bail!("Remote media is too large ({} bytes > max {} bytes)", len, max_bytes);
        }
    }

    if let Some(ct) = content_type.as_deref() {
        if ct.contains("text/html") || ct.contains("application/xhtml") {
            anyhow::bail!("Remote response was HTML, not media. Final URL: {}", resp.url());
        }
    }

    let mut out = std::fs::File::create(path)?;
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = resp.read(&mut buffer)?;
        if read == 0 { break; }
        total = total.saturating_add(read as u64);
        if total > max_bytes {
            anyhow::bail!("Remote media exceeded max size ({} bytes > max {} bytes)", total, max_bytes);
        }
        out.write_all(&buffer[..read])?;
    }
    out.sync_all()?;
    Ok(())
}

fn resolve_media_url(client: &Client, start_url: &str, max_hops: usize) -> anyhow::Result<String> {
    let mut current = start_url.to_string();
    let mut visited: HashSet<String> = HashSet::new();
    let target_name = extract_filename(start_url);

    for _ in 0..max_hops {
        if !visited.insert(current.clone()) {
            anyhow::bail!("URL resolution loop detected for {}", current);
        }

        let resp = client.get(&current)
            .header(RANGE, "bytes=0-2047")
            .send();

        let mut resp = match resp {
            Ok(r) => r,
            Err(e) => anyhow::bail!("Failed to fetch URL {}: {}", current, e),
        };

        let final_url = resp.url().to_string();
        let content_type = resp.headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_ascii_lowercase());

        let mut sniff = [0u8; 2048];
        let read_len = resp.read(&mut sniff)?;
        if read_len > 0 && looks_like_media(&sniff[..read_len]) {
            return Ok(final_url);
        }

        // Try a curl-like resolution as a fallback for sites that behave differently
        // depending on User-Agent / request patterns (e.g., filebin links).
        if let Ok(Some(curl_final)) = try_curl_like_resolution(&current) {
            return Ok(curl_final);
        }

        if let Some(ct) = content_type.as_deref() {
            if !ct.contains("text/html") && !ct.contains("application/xhtml") {
                return Ok(final_url);
            }
        }

        let mut html = String::new();
        let _ = html.push_str(&String::from_utf8_lossy(&sniff[..read_len]));
        let _ = resp.read_to_string(&mut html);
        let base = Url::parse(&final_url).ok();
        let mut candidates = extract_url_candidates(&html)
            .into_iter()
            .filter(|c| c != &current)
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            anyhow::bail!("Unable to resolve media URL from HTML content at {}", final_url);
        }

        score_candidates(&mut candidates, target_name.as_deref());
        let resolved = pick_best_candidate(client, &candidates, base.as_ref(), target_name.as_deref())?;
        info!("Following HTML redirect to: {}", resolved);
        current = resolved;
        continue;
    }

    anyhow::bail!("URL resolution exceeded {} hops for {}", max_hops, start_url);
}

fn extract_url_candidates(html: &str) -> Vec<String> {
    let mut out = Vec::new();

    // meta refresh
    for chunk in html.split("<meta") {
        if let Some(idx) = chunk.find("url=") {
            let tail = &chunk[idx + 4..];
            if let Some(url) = read_until_delim(tail) {
                out.push(url);
            }
        }
    }

    // href="..."
    for chunk in html.split("href=") {
        if let Some(url) = read_quoted_or_plain(chunk) {
            out.push(url);
        }
    }

    // data-url / data-href / data-download
    for key in ["data-url=", "data-href=", "data-download="] {
        for chunk in html.split(key) {
            if let Some(url) = read_quoted_or_plain(chunk) {
                out.push(url);
            }
        }
    }

    // plain http(s)
    for prefix in ["https://", "http://"] {
        let mut start = 0;
        while let Some(pos) = html[start..].find(prefix) {
            let idx = start + pos;
            let tail = &html[idx..];
            if let Some(url) = read_until_delim(tail) {
                out.push(url);
            }
            start = idx + prefix.len();
        }
    }

    out
}

fn looks_like_media(buf: &[u8]) -> bool {
    if buf.len() >= 3 && buf[0] == 0xFF && buf[1] == 0xD8 && buf[2] == 0xFF {
        return true; // JPEG
    }
    if buf.len() >= 8 && &buf[0..8] == b"\x89PNG\r\n\x1a\n" {
        return true; // PNG
    }
    if buf.len() >= 12 && &buf[0..4] == b"RIFF" && &buf[8..12] == b"WEBP" {
        return true; // WEBP
    }
    if buf.len() >= 12 {
        if &buf[4..8] == b"ftyp" {
            return true; // MP4/MOV
        }
    }
    false
}

fn score_candidates(candidates: &mut Vec<String>, target_name: Option<&str>) {
    candidates.sort_by(|a, b| score_candidate(b, target_name).cmp(&score_candidate(a, target_name)));
}

fn score_candidate(url: &str, target_name: Option<&str>) -> i32 {
    let mut score = 0;
    let lower = url.to_ascii_lowercase();

    if lower.contains("/static/") || lower.contains("favicon") {
        score -= 50;
    }

    if let Some(name) = target_name {
        if lower.contains(&name.to_ascii_lowercase()) {
            score += 50;
        }
    }

    if lower.contains("x-amz-") || lower.contains("signature=") {
        score += 15;
    }

    if lower.ends_with(".jpg") || lower.ends_with(".jpeg") || lower.ends_with(".png") || lower.ends_with(".webp") || lower.ends_with(".mp4") || lower.ends_with(".mov") || lower.ends_with(".m4v") {
        score += 10;
    }

    score
}

fn pick_best_candidate(client: &Client, candidates: &[String], base: Option<&Url>, target_name: Option<&str>) -> anyhow::Result<String> {
    let mut tried = 0;
    for candidate in candidates.iter().take(12) {
        let url = normalize_url(candidate, base)?;
        if let Some(name) = target_name {
            if !url.to_ascii_lowercase().contains(&name.to_ascii_lowercase()) {
                if tried < 3 {
                    // still probe a few even without name match
                } else {
                    continue;
                }
            }
        }

        tried += 1;
        if let Ok(res) = probe_media_url(client, &url) {
            if res {
                return Ok(url);
            }
        }
    }

    // Fallback to first normalized candidate
    if let Some(first) = candidates.first() {
        return Ok(normalize_url(first, base)?);
    }

    anyhow::bail!("No viable URL candidates found")
}

fn probe_media_url(client: &Client, url: &str) -> io::Result<bool> {
    let resp = client.head(url).send();
    if let Ok(res) = resp {
        let ct = res.headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_ascii_lowercase());
        if let Some(ct) = ct.as_deref() {
            if ct.contains("text/html") || ct.contains("application/xhtml") {
                return Ok(false);
            }
            if ct.contains("image/") || ct.contains("video/") || ct.contains("application/octet-stream") {
                return Ok(true);
            }
        }
    }

    let res = client.get(url)
        .header(RANGE, "bytes=0-0")
        .send();

    if let Ok(res) = res {
        let ct = res.headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_ascii_lowercase());
        if let Some(ct) = ct.as_deref() {
            if ct.contains("text/html") || ct.contains("application/xhtml") {
                return Ok(false);
            }
            if ct.contains("image/") || ct.contains("video/") || ct.contains("application/octet-stream") {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

fn extract_filename(url: &str) -> Option<String> {
    let url_no_query = url.split('?').next().unwrap_or(url);
    let name = url_no_query.rsplit('/').next().unwrap_or("").trim();
    if name.is_empty() { None } else { Some(name.to_string()) }
}

fn read_until_delim(s: &str) -> Option<String> {
    let end = s.find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '<' || c == '>')
        .unwrap_or(s.len());
    let candidate = s[..end].trim();
    if candidate.is_empty() { None } else { Some(candidate.to_string()) }
}

fn read_quoted_or_plain(s: &str) -> Option<String> {
    let s = s.trim_start();
    if s.is_empty() { return None; }
    let first = s.chars().next()?;
    if first == '"' || first == '\'' {
        let rest = &s[1..];
        let end = rest.find(first).unwrap_or(rest.len());
        let candidate = &rest[..end];
        if candidate.is_empty() { None } else { Some(candidate.to_string()) }
    } else {
        read_until_delim(s)
    }
}

fn normalize_url(candidate: &str, base: Option<&Url>) -> anyhow::Result<String> {
    if candidate.starts_with("http://") || candidate.starts_with("https://") {
        Ok(candidate.to_string())
    } else if let Some(base) = base {
        Ok(base.join(candidate)?.to_string())
    } else {
        anyhow::bail!("Relative URL without base: {}", candidate)
    }
}

fn max_download_bytes() -> u64 {
    std::env::var("MIRAGE_URL_MAX_BYTES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(DEFAULT_MAX_DOWNLOAD_BYTES)
}

fn read_ahead_bytes() -> usize {
    std::env::var("MIRAGE_URL_READAHEAD")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(DEFAULT_READAHEAD_BYTES)
}

fn try_curl_like_resolution(start: &str) -> anyhow::Result<Option<String>> {
    // Create a client that resembles curl and follows redirects aggressively.
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(Policy::limited(20))
        .user_agent("curl/7.85.0")
        .build()?;

    // Prefer HEAD first
    if let Ok(resp) = client.head(start).send() {
        if resp.status().is_success() {
            let final_url = resp.url().to_string();
            if let Some(ct) = resp.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()) {
                let ct = ct.to_ascii_lowercase();
                if ct.contains("image/") || ct.contains("video/") || ct.contains("application/octet-stream") {
                    return Ok(Some(final_url));
                }
            }
            // If Location header present and pointing to an S3/signed URL, prefer it
            if let Some(loc) = resp.headers().get("Location").and_then(|v| v.to_str().ok()) {
                if loc.contains("s3.filebin.net") || loc.contains("amazonaws.com") || loc.contains("x-amz-signature") {
                    return Ok(Some(loc.to_string()));
                }
            }
        }
    }

    // Fallback to GET with small range to sniff bytes
    if let Ok(mut resp) = client.get(start).header(RANGE, "bytes=0-2047").send() {
        if resp.status().is_success() || resp.status().as_u16() == 206 {
            let final_url = resp.url().to_string();
            let mut sniff = [0u8; 2048];
            let read_len = resp.read(&mut sniff).unwrap_or(0);
            if read_len > 0 && looks_like_media(&sniff[..read_len]) {
                return Ok(Some(final_url));
            }
        }
    }

    Ok(None)
}

struct ReadOnlyDevice {
    inner: Box<dyn BlockDevice>,
    _temp_dir: Option<TempDir>,
}

impl ReadOnlyDevice {
    fn new(inner: Box<dyn BlockDevice>, temp_dir: Option<TempDir>) -> Self {
        Self { inner, _temp_dir: temp_dir }
    }
}

impl BlockDevice for ReadOnlyDevice {
    fn block_count(&self) -> u64 { self.inner.block_count() }
    fn read_block(&self, index: u32) -> io::Result<[u8; BLOCK_SIZE]> {
        self.inner.read_block(index)
    }
    fn write_block(&mut self, _index: u32, _data: &[u8; BLOCK_SIZE]) -> io::Result<()> {
        Err(Error::new(ErrorKind::PermissionDenied, "Read-only media URL"))
    }
    fn resize(&mut self, _block_count: u64) -> io::Result<()> {
        Err(Error::new(ErrorKind::PermissionDenied, "Read-only media URL"))
    }
    fn sync(&mut self) -> io::Result<()> { Ok(()) }
    fn is_expandable(&self) -> bool { self.inner.is_expandable() }
}

struct HttpRangeReader {
    client: Client,
    origin_url: String,
    url: std::sync::Mutex<String>,
    content_length: std::sync::Mutex<u64>,
    cache: std::sync::Mutex<Option<RangeCache>>,
}

struct RangeCache {
    start: u64,
    data: Vec<u8>,
}

impl HttpRangeReader {
    fn new(client: Client, origin_url: String, url: String, content_length: Option<u64>) -> io::Result<Self> {
        let mut content_len = content_length;
        let mut accept_ranges = false;

        if let Ok(res) = client.head(&url).send() {
            if res.status().is_success() {
                accept_ranges = res.headers()
                    .get(ACCEPT_RANGES)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_ascii_lowercase().contains("bytes"))
                    .unwrap_or(false);

                if content_len.is_none() {
                    content_len = res.headers()
                        .get(CONTENT_LENGTH)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok());
                }
            }
        }

        if content_len.is_none() || !accept_ranges {
            let (len, supports) = probe_range(&client, &url)?;
            content_len = Some(len);
            accept_ranges = supports;
        }

        if !accept_ranges {
            return Err(Error::new(ErrorKind::Unsupported, "Remote server does not support byte ranges"));
        }

        let content_length = content_len.ok_or_else(|| Error::new(ErrorKind::InvalidData, "Missing content length for remote media"))?;

        Ok(Self {
            client,
            origin_url,
            url: std::sync::Mutex::new(url),
            content_length: std::sync::Mutex::new(content_length),
            cache: std::sync::Mutex::new(None),
        })
    }

    fn read_range(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }

        if let Some(buf) = self.try_read_from_cache(offset, len) {
            return Ok(buf);
        }

        let mut content_length = *self.content_length.lock().map_err(|_| {
            Error::new(ErrorKind::Other, "Range reader poisoned")
        })?;
        if offset >= content_length {
            // Attempt refresh in case a signed URL expired or length changed.
            if self.refresh_url().is_ok() {
                content_length = *self.content_length.lock().map_err(|_| {
                    Error::new(ErrorKind::Other, "Range reader poisoned")
                })?;
            }
            if offset >= content_length {
                return Err(Error::new(ErrorKind::UnexpectedEof, "Offset beyond EOF"));
            }
        }

        let read_ahead = read_ahead_bytes();
        let fetch_len = std::cmp::max(len, read_ahead);
        let end = std::cmp::min(offset + fetch_len as u64 - 1, content_length - 1);
        let expected_len = (end - offset + 1) as usize;
        let range_header = format!("bytes={}-{}", offset, end);

        let url = self.url.lock().map_err(|_| Error::new(ErrorKind::Other, "Range reader poisoned"))?.clone();
        match self.try_read_range(&url, &range_header, expected_len) {
            Ok(buf) => {
                self.update_cache(offset, buf.clone());
                let return_len = std::cmp::min(len, buf.len());
                Ok(buf[..return_len].to_vec())
            }
            Err(e) => {
                // Attempt a refresh (e.g., signed URL expired) and retry once.
                if self.refresh_url().is_ok() {
                    let refreshed_url = self.url.lock().map_err(|_| Error::new(ErrorKind::Other, "Range reader poisoned"))?.clone();
                    return self.try_read_range(&refreshed_url, &range_header, expected_len)
                        .map(|buf| {
                            self.update_cache(offset, buf.clone());
                            let return_len = std::cmp::min(len, buf.len());
                            buf[..return_len].to_vec()
                        })
                        .map_err(|_| e);
                }
                Err(e)
            }
        }
    }

    fn try_read_from_cache(&self, offset: u64, len: usize) -> Option<Vec<u8>> {
        let cache = self.cache.lock().ok()?;
        let cache = cache.as_ref()?;
        let start = cache.start;
        let end = start.saturating_add(cache.data.len() as u64);
        let req_end = offset.saturating_add(len as u64);

        if offset >= start && req_end <= end {
            let start_idx = (offset - start) as usize;
            let end_idx = start_idx + len;
            return Some(cache.data[start_idx..end_idx].to_vec());
        }
        None
    }

    fn update_cache(&self, offset: u64, data: Vec<u8>) {
        if let Ok(mut cache) = self.cache.lock() {
            *cache = Some(RangeCache { start: offset, data });
        }
    }

    fn try_read_range(&self, url: &str, range_header: &str, expected_len: usize) -> io::Result<Vec<u8>> {
        let mut resp = self.client.get(url)
            .header(RANGE, range_header)
            .send()
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

        let status = resp.status().as_u16();
        if status != 206 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!("Server did not honor range request (HTTP {})", status),
            ));
        }

        // Update content length from Content-Range if present.
        if let Some(total) = resp.headers()
            .get(CONTENT_RANGE)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_content_range_total)
        {
            if let Ok(mut len_lock) = self.content_length.lock() {
                *len_lock = total;
            }
        }

        let mut buf = Vec::with_capacity(expected_len);
        resp.read_to_end(&mut buf)?;
        if buf.len() != expected_len {
            return Err(Error::new(ErrorKind::UnexpectedEof, "Short read from remote media"));
        }
        Ok(buf)
    }

    fn refresh_url(&self) -> io::Result<()> {
        let resolved = resolve_media_url(&self.client, &self.origin_url, 8)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
        let head = fetch_head_info(&self.client, &resolved);
        let length = head.content_length.ok_or_else(|| Error::new(ErrorKind::InvalidData, "Missing content length for remote media"))?;

        let mut url_lock = self.url.lock().map_err(|_| Error::new(ErrorKind::Other, "Range reader poisoned"))?;
        let mut len_lock = self.content_length.lock().map_err(|_| Error::new(ErrorKind::Other, "Range reader poisoned"))?;
        *url_lock = head.final_url;
        *len_lock = length;
        Ok(())
    }

    fn len(&self) -> u64 {
        *self.content_length.lock().unwrap_or_else(|p| p.into_inner())
    }
}

fn probe_range(client: &Client, url: &str) -> io::Result<(u64, bool)> {
    let mut resp = client.get(url)
        .header(RANGE, "bytes=0-0")
        .send()
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

    let status = resp.status().as_u16();
    if status != 206 {
        return Ok((0, false));
    }

    let total = resp.headers()
        .get(CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_content_range_total)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Missing Content-Range in range response"))?;

    let mut buf = Vec::new();
    let _ = resp.read_to_end(&mut buf);

    Ok((total, true))
}

fn parse_content_range_total(value: &str) -> Option<u64> {
    // Example: "bytes 0-0/12345"
    let total = value.split('/').nth(1)?;
    if total == "*" { return None; }
    total.parse::<u64>().ok()
}

pub struct UrlMp4Disk {
    reader: HttpRangeReader,
    cipher: ChaCha20Poly1305,
    data_start_offset: u64,
    data_length: u64,
}

impl UrlMp4Disk {
    fn new(reader: HttpRangeReader, password: &str) -> io::Result<Self> {
        let (mdat_offset, mdat_size, exists) = Self::scan_for_mirage_mdat(&reader)?;
        if !exists {
            return Err(Error::new(ErrorKind::InvalidData, "No MirageFS (Shadow mdat) found in MP4 URL"));
        }

        let data_start = mdat_offset + 8;
        let current_payload_len = mdat_size - 8;

        // Read first NAL (Magic + Salt)
        let first_len = NAL_OVERHEAD + MIRAGE_MAGIC.len() + SALT_SIZE;
        let first_nal = reader.read_range(data_start, first_len)?;

        if first_nal.len() < first_len || first_nal[0..4] != NAL_PREFIX || first_nal[4] != NAL_FILLER_TYPE {
            return Err(Error::new(ErrorKind::InvalidData, "Corrupt NAL encapsulation"));
        }

        let payload_start = NAL_OVERHEAD;
        if &first_nal[payload_start..payload_start + 8] != MIRAGE_MAGIC {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid Magic in Shadow mdat"));
        }

        let salt = &first_nal[payload_start + 8..payload_start + 8 + SALT_SIZE];

        debug!("MP4 URL: Deriving keys from remote video stream headers...");
        let salt_string = SaltString::encode_b64(salt)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt_string)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

        let hash_output = password_hash.hash.ok_or_else(|| Error::new(ErrorKind::Other, "Hash failed"))?;
        let mut key_buffer = [0u8; 32];
        key_buffer.copy_from_slice(&hash_output.as_bytes()[0..32]);

        let key = Key::from_slice(&key_buffer);
        let cipher = ChaCha20Poly1305::new(key);

        Ok(Self {
            reader,
            cipher,
            data_start_offset: data_start,
            data_length: current_payload_len,
        })
    }

    fn scan_for_mirage_mdat(reader: &HttpRangeReader) -> io::Result<(u64, u64, bool)> {
        let len = reader.len();
        let mut pos = 0u64;

        while pos < len {
            let header = reader.read_range(pos, 8)?;
            if header.len() < 8 { break; }

            let mut size = u32::from_be_bytes(header[0..4].try_into().unwrap()) as u64;
            let type_bytes = &header[4..8];
            let mut header_len = 8u64;

            if size == 1 {
                let ext = reader.read_range(pos + 8, 8)?;
                if ext.len() < 8 { break; }
                size = u64::from_be_bytes(ext[0..8].try_into().unwrap());
                header_len = 16;
            } else if size == 0 {
                size = len - pos;
            }

            if type_bytes == &ATOM_MDAT {
                let peek_len = NAL_OVERHEAD + MIRAGE_MAGIC.len();
                let peek_offset = pos + header_len;
                if peek_offset + peek_len as u64 <= len {
                    let peek = reader.read_range(peek_offset, peek_len)?;
                    if peek.len() >= peek_len
                        && peek[0..4] == NAL_PREFIX
                        && peek[4] == NAL_FILLER_TYPE
                        && &peek[5..5 + MIRAGE_MAGIC.len()] == MIRAGE_MAGIC
                    {
                        info!("Found MirageFS Shadow mdat at offset {}", pos);
                        return Ok((pos, size, true));
                    }
                }
            }

            if size == 0 { break; }
            pos += size;
        }

        Ok((0, 0, false))
    }
}

impl BlockDevice for UrlMp4Disk {
    fn is_expandable(&self) -> bool { true }

    fn block_count(&self) -> u64 {
        let header_nal_len = NAL_OVERHEAD + MIRAGE_MAGIC.len() + SALT_SIZE;
        if self.data_length <= header_nal_len as u64 { return 0; }
        (self.data_length - header_nal_len as u64) / NAL_PACKET_SIZE as u64
    }

    fn read_block(&self, index: u32) -> io::Result<[u8; BLOCK_SIZE]> {
        let header_nal_len = NAL_OVERHEAD + MIRAGE_MAGIC.len() + SALT_SIZE;
        let offset = self.data_start_offset + header_nal_len as u64 + (index as u64 * NAL_PACKET_SIZE as u64);

        if offset + NAL_PACKET_SIZE as u64 > self.data_start_offset + self.data_length {
            return Ok([0u8; BLOCK_SIZE]);
        }

        let packet = self.reader.read_range(offset, NAL_PACKET_SIZE)?;
        if packet.len() != NAL_PACKET_SIZE {
            return Err(Error::new(ErrorKind::UnexpectedEof, "Short read from remote MP4"));
        }

        if packet[0..4] != NAL_PREFIX || packet[4] != NAL_FILLER_TYPE {
            warn!("MP4 URL: Bad NAL wrapper at block {}", index);
            return Err(Error::new(ErrorKind::InvalidData, "Stream Synchronization Lost"));
        }

        let encrypted_data = &packet[NAL_OVERHEAD..];
        let nonce = Nonce::from_slice(&encrypted_data[0..12]);
        let ciphertext = &encrypted_data[12..];

        match self.cipher.decrypt(nonce, Payload { msg: ciphertext, aad: &[] }) {
            Ok(plaintext) => {
                let mut buffer = [0u8; BLOCK_SIZE];
                buffer.copy_from_slice(&plaintext);
                Ok(buffer)
            }
            Err(_) => {
                warn!("MP4 URL: Decrypt failed at block {}", index);
                Err(Error::new(ErrorKind::PermissionDenied, "Auth Tag Mismatch"))
            }
        }
    }

    fn write_block(&mut self, _index: u32, _data: &[u8; BLOCK_SIZE]) -> io::Result<()> {
        Err(Error::new(ErrorKind::PermissionDenied, "Read-only media URL"))
    }

    fn resize(&mut self, _block_count: u64) -> io::Result<()> {
        Err(Error::new(ErrorKind::PermissionDenied, "Read-only media URL"))
    }

    fn sync(&mut self) -> io::Result<()> { Ok(()) }
}
