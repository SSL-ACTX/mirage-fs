// src/webdav_server.rs
use crate::mirage_fs::{MirageFS, MirageFileType};
use crate::url_media::url_metrics_json;
#[path = "web_assets.rs"]
mod web_assets;

use dav_server::{
    fs::{DavDirEntry, DavFile, DavFileSystem, DavMetaData, FsError, FsFuture, FsResult, OpenOptions},
    davpath::DavPath,
    DavHandler,
    body::Body,
};
use std::sync::{Arc, Mutex};
use std::io::SeekFrom;
use std::net::SocketAddr;
use std::time::SystemTime;
use futures::FutureExt;
use bytes::{Bytes, Buf};
use dav_server::fakels::FakeLs;
use hyper::Method;

// --- Error Mapping Helper ---
fn map_err(code: i32) -> FsError {
    match code {
        libc::ENOENT => FsError::NotFound,
        libc::EEXIST => FsError::Exists,
        libc::EACCES | libc::EPERM => FsError::Forbidden,
        libc::ENOTEMPTY => FsError::Forbidden,
        _ => FsError::GeneralFailure,
    }
}

// --- Helper Structs ---

#[derive(Clone)]
pub struct MirageWebDav {
    fs: Arc<Mutex<MirageFS>>,
}

impl MirageWebDav {
    pub fn new(fs: MirageFS) -> Self {
        Self {
            fs: Arc::new(Mutex::new(fs)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MirageMetaData {
    len: u64,
    modified: SystemTime,
    is_dir: bool,
}

impl DavMetaData for MirageMetaData {
    fn len(&self) -> u64 { self.len }
    fn modified(&self) -> FsResult<SystemTime> { Ok(self.modified) }
    fn is_dir(&self) -> bool { self.is_dir }
    fn created(&self) -> FsResult<SystemTime> { Ok(self.modified) }
}

#[derive(Clone, Debug)]
pub struct MirageDirEntry {
    name: Vec<u8>,
    meta: MirageMetaData,
}

impl DavDirEntry for MirageDirEntry {
    fn name(&self) -> Vec<u8> {
        self.name.clone()
    }

    fn metadata(&self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        let meta = self.meta.clone();
        async move {
            Ok(Box::new(meta) as Box<dyn DavMetaData>)
        }.boxed()
    }
}

#[derive(Debug)]
pub struct MirageDavFile {
    fs: Arc<Mutex<MirageFS>>,
    ino: u64,
    current_pos: u64,
}

// --- DavFile Implementation ---
impl DavFile for MirageDavFile {
    fn read_bytes(&mut self, count: usize) -> FsFuture<'_, Bytes> {
        let fs = self.fs.clone();
        let ino = self.ino;
        let pos = self.current_pos;

        async move {
            let read_result = tokio::task::spawn_blocking(move || {
                let mut locked_fs = fs.lock().unwrap();
                locked_fs.read_data_internal(ino, pos, count as u32)
            })
            .await
            .map_err(|_| FsError::GeneralFailure)?;

            match read_result {
                Ok(data) => {
                    self.current_pos += data.len() as u64;
                    Ok(Bytes::from(data))
                },
                Err(e) => Err(map_err(e)),
            }
        }.boxed()
    }

    fn write_bytes(&mut self, buf: Bytes) -> FsFuture<'_, ()> {
        let b = Box::new(buf);
        self.write_buf(b)
    }

    fn write_buf(&mut self, mut buf: Box<dyn Buf + Send>) -> FsFuture<'_, ()> {
        let fs = self.fs.clone();
        let ino = self.ino;
        let pos = self.current_pos;

        async move {
            let mut data_to_write = Vec::new();
            while buf.has_remaining() {
                let chunk = buf.chunk();
                data_to_write.extend_from_slice(chunk);
                buf.advance(chunk.len());
            }

            let result = tokio::task::spawn_blocking(move || {
                let mut locked_fs = fs.lock().unwrap();
                locked_fs.write_data_internal(ino, pos, &data_to_write)
            })
            .await
            .map_err(|_| FsError::GeneralFailure)?;

            match result {
                Ok(written) => {
                    self.current_pos += written as u64;
                    Ok(())
                },
                Err(e) => Err(map_err(e)),
            }
        }.boxed()
    }

    fn seek(&mut self, pos: SeekFrom) -> FsFuture<'_, u64> {
        let fs = self.fs.clone();
        let ino = self.ino;
        let current_pos = self.current_pos;

        async move {
            let size = tokio::task::spawn_blocking(move || {
                let locked_fs = fs.lock().unwrap();
                locked_fs.get_inode_size(ino).unwrap_or(0)
            }).await.map_err(|_| FsError::GeneralFailure)?;

            let new_pos = match pos {
                SeekFrom::Start(p) => p,
                SeekFrom::Current(p) => (current_pos as i64 + p) as u64,
                SeekFrom::End(p) => (size as i64 + p) as u64,
            };

            self.current_pos = new_pos;
            Ok(new_pos)
        }.boxed()
    }

    fn flush(&mut self) -> FsFuture<'_, ()> {
        let fs = self.fs.clone();
        async move {
            let res = tokio::task::spawn_blocking(move || {
                let mut locked_fs = fs.lock().unwrap();
                locked_fs.sync_disk()
            })
            .await
            .map_err(|_| FsError::GeneralFailure)?;

            if res == 0 {
                Ok(())
            } else {
                Err(FsError::GeneralFailure)
            }
        }.boxed()
    }

    fn metadata(&mut self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        let fs = self.fs.clone();
        let ino = self.ino;
        async move {
            let meta = tokio::task::spawn_blocking(move || {
                let locked_fs = fs.lock().unwrap();
                if let Some(inode) = locked_fs.get_inode(ino) {
                    Ok(MirageMetaData {
                        len: inode.attr.size,
                        modified: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(inode.attr.mtime_secs),
                       is_dir: match inode.attr.kind { MirageFileType::Directory => true, _ => false },
                    })
                } else {
                    Err(FsError::NotFound)
                }
            }).await.map_err(|_| FsError::GeneralFailure)?;

            match meta {
                Ok(m) => Ok(Box::new(m) as Box<dyn DavMetaData>),
                Err(e) => Err(e),
            }
        }.boxed()
    }
}

// --- DavFileSystem Implementation ---
impl DavFileSystem for MirageWebDav {
    fn open(&self, path: &DavPath, options: OpenOptions) -> FsFuture<'_, Box<dyn DavFile>> {
        let fs = self.fs.clone();
        let path_str = path.as_pathbuf().to_string_lossy().to_string();

        async move {
            let fs_for_task = fs.clone();
            let ino_opt = tokio::task::spawn_blocking(move || {
                let mut locked_fs = fs_for_task.lock().unwrap();

                if options.create {
                    let p = std::path::Path::new(&path_str);
                    if let Some(parent) = p.parent() {
                        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                        if let Ok(parent_ino) = locked_fs.resolve_path(parent) {
                            // Check if exists
                            if let Ok(existing) = locked_fs.resolve_path(p) {
                                // Truncate if requested
                                if options.truncate {
                                    // Assuming size 0 implies truncate start
                                    let _ = locked_fs.set_attr_internal(existing, Some(0), None, None);
                                }
                                return Ok(existing);
                            }
                            if let Ok(new_ino) = locked_fs.create_file_internal(parent_ino, name) {
                                return Ok(new_ino);
                            }
                        }
                    }
                }

                locked_fs.resolve_path(std::path::Path::new(&path_str))
            }).await.unwrap();

            match ino_opt {
                Ok(ino) => Ok(Box::new(MirageDavFile { fs: fs, ino, current_pos: 0 }) as Box<dyn DavFile>),
                Err(_) => Err(FsError::NotFound),
            }
        }.boxed()
    }

    fn read_dir<'a>(&'a self, path: &'a DavPath, _meta: dav_server::fs::ReadDirMeta) -> FsFuture<'a, std::pin::Pin<Box<dyn futures::Stream<Item = FsResult<Box<dyn DavDirEntry>>> + Send>>> {
        let fs = self.fs.clone();
        let path_str = path.as_pathbuf().to_string_lossy().to_string();

        async move {
            let entries = tokio::task::spawn_blocking(move || {
                let locked_fs = fs.lock().unwrap();
                if let Ok(ino) = locked_fs.resolve_path(std::path::Path::new(&path_str)) {
                    locked_fs.readdir_internal(ino)
                } else {
                    Vec::new()
                }
            }).await.unwrap();

            let stream = futures::stream::iter(entries.into_iter().map(|(_ino, name, kind)| {
                // Return dummy metadata for listing; real metadata fetched on demand
                let meta = MirageMetaData {
                    len: 0,
                    modified: SystemTime::now(),
                                                                       is_dir: match kind { MirageFileType::Directory => true, _ => false }
                };

                let entry = MirageDirEntry {
                    name: name.into_bytes(),
                                                                       meta,
                };

                Ok(Box::new(entry) as Box<dyn DavDirEntry>)
            }));

            Ok(Box::pin(stream) as std::pin::Pin<Box<dyn futures::Stream<Item = FsResult<Box<dyn DavDirEntry>>> + Send>>)
        }.boxed()
    }

    fn metadata(&self, path: &DavPath) -> FsFuture<'_, Box<dyn DavMetaData>> {
        let fs = self.fs.clone();
        let path_str = path.as_pathbuf().to_string_lossy().to_string();

        async move {
            let meta = tokio::task::spawn_blocking(move || {
                let locked_fs = fs.lock().unwrap();
                if let Ok(ino) = locked_fs.resolve_path(std::path::Path::new(&path_str)) {
                    if let Some(inode) = locked_fs.get_inode(ino) {
                        return Ok(MirageMetaData {
                            len: inode.attr.size,
                            modified: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(inode.attr.mtime_secs),
                                  is_dir: match inode.attr.kind { MirageFileType::Directory => true, _ => false },
                        });
                    }
                }
                Err(libc::ENOENT)
            }).await.unwrap();

            match meta {
                Ok(m) => Ok(Box::new(m) as Box<dyn DavMetaData>),
                Err(e) => Err(map_err(e)),
            }
        }.boxed()
    }

    fn create_dir(&self, path: &DavPath) -> FsFuture<'_, ()> {
        let fs = self.fs.clone();
        let path_str = path.as_pathbuf().to_string_lossy().to_string();
        async move {
            let res = tokio::task::spawn_blocking(move || {
                let mut locked_fs = fs.lock().unwrap();
                let p = std::path::Path::new(&path_str);
                if let Some(parent) = p.parent() {
                    let name = p.file_name().unwrap().to_str().unwrap();
                    if let Ok(parent_ino) = locked_fs.resolve_path(parent) {
                        return locked_fs.mkdir_internal(parent_ino, name);
                    }
                }
                Err(libc::EIO)
            }).await.unwrap();

            match res {
                Ok(_) => Ok(()),
                Err(e) => Err(map_err(e)),
            }
        }.boxed()
    }

    fn remove_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        let fs = self.fs.clone();
        let path_str = path.as_pathbuf().to_string_lossy().to_string();
        async move {
            let res = tokio::task::spawn_blocking(move || {
                let mut locked_fs = fs.lock().unwrap();
                let p = std::path::Path::new(&path_str);
                if let Some(parent) = p.parent() {
                    let name = p.file_name().unwrap().to_str().unwrap();
                    if let Ok(parent_ino) = locked_fs.resolve_path(parent) {
                        return locked_fs.rmdir_internal(parent_ino, name);
                    }
                }
                Err(libc::ENOENT)
            }).await.unwrap();

            match res {
                Ok(_) => Ok(()),
                Err(e) => Err(map_err(e)),
            }
        }.boxed()
    }

    fn remove_file<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        let fs = self.fs.clone();
        let path_str = path.as_pathbuf().to_string_lossy().to_string();
        async move {
            let res = tokio::task::spawn_blocking(move || {
                let mut locked_fs = fs.lock().unwrap();
                let p = std::path::Path::new(&path_str);
                if let Some(parent) = p.parent() {
                    let name = p.file_name().unwrap().to_str().unwrap();
                    if let Ok(parent_ino) = locked_fs.resolve_path(parent) {
                        return locked_fs.unlink_internal(parent_ino, name);
                    }
                }
                Err(libc::ENOENT)
            }).await.unwrap();

            match res {
                Ok(_) => Ok(()),
                Err(e) => Err(map_err(e)),
            }
        }.boxed()
    }

    fn rename(&self, from: &DavPath, to: &DavPath) -> FsFuture<'_, ()> {
        let fs = self.fs.clone();
        let from_str = from.as_pathbuf().to_string_lossy().to_string();
        let to_str = to.as_pathbuf().to_string_lossy().to_string();

        async move {
            let res = tokio::task::spawn_blocking(move || {
                let mut locked_fs = fs.lock().unwrap();
                let p_from = std::path::Path::new(&from_str);
                let p_to = std::path::Path::new(&to_str);

                let parent_from = p_from.parent().ok_or(libc::EIO)?;
                let name_from = p_from.file_name().ok_or(libc::EIO)?.to_str().unwrap();

                let parent_to = p_to.parent().ok_or(libc::EIO)?;
                let name_to = p_to.file_name().ok_or(libc::EIO)?.to_str().unwrap();

                let parent_ino_from = locked_fs.resolve_path(parent_from).map_err(|e| e)?;
                let parent_ino_to = locked_fs.resolve_path(parent_to).map_err(|e| e)?;

                locked_fs.rename_internal(parent_ino_from, name_from, parent_ino_to, name_to)
            }).await.unwrap();

            match res {
                Ok(_) => Ok(()),
                Err(e) => Err(map_err(e)),
            }
        }.boxed()
    }

    fn copy(&self, from: &DavPath, to: &DavPath) -> FsFuture<'_, ()> {
        let fs = self.fs.clone();
        let from_str = from.as_pathbuf().to_string_lossy().to_string();
        let to_str = to.as_pathbuf().to_string_lossy().to_string();

        async move {
            let res = tokio::task::spawn_blocking(move || {
                let mut locked_fs = fs.lock().unwrap();

                // 1. Resolve Source
                let src_ino = locked_fs.resolve_path(std::path::Path::new(&from_str)).map_err(|_| libc::ENOENT)?;

                // 2. Resolve Dest Parent
                let p_to = std::path::Path::new(&to_str);
                let parent_to = p_to.parent().ok_or(libc::EIO)?;
                let name_to = p_to.file_name().ok_or(libc::EIO)?.to_str().unwrap();
                let parent_ino_to = locked_fs.resolve_path(parent_to).map_err(|_| libc::ENOENT)?;

                // 3. Create Dest File
                let dest_ino = locked_fs.create_file_internal(parent_ino_to, name_to).map_err(|e| e)?;

                // 4. Perform Deep Copy (Read Src -> Write Dest)
                let size = locked_fs.get_inode_size(src_ino).unwrap_or(0);
                let mut offset = 0;
                let chunk_size = 64 * 1024; // 64KB chunks

                while offset < size {
                    let read_len = std::cmp::min(chunk_size, (size - offset) as u32);
                    if let Ok(data) = locked_fs.read_data_internal(src_ino, offset, read_len) {
                        if let Err(_) = locked_fs.write_data_internal(dest_ino, offset, &data) {
                            return Err(libc::EIO);
                        }
                        offset += data.len() as u64;
                    } else {
                        return Err(libc::EIO);
                    }
                }
                Ok(())
            }).await.unwrap();

            match res {
                Ok(_) => Ok(()),
                Err(e) => Err(map_err(e)),
            }
        }.boxed()
    }
}

pub async fn start_webdav_server(fs: MirageFS, port: u16) {
    let dav_server = DavHandler::builder()
    .filesystem(Box::new(MirageWebDav::new(fs)))
    .locksystem(FakeLs::new())
    .build_handler();

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("🌐 WebDAV Server running at http://{}/", addr);
    println!("   -> Connect via Browser for UI: http://127.0.0.1:{}", port);
    println!("   -> Connect via WebDAV Client:  http://127.0.0.1:{}", port);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let io = hyper_util::rt::TokioIo::new(stream);
        let dav_server = dav_server.clone();

        tokio::task::spawn(async move {
            let service = hyper::service::service_fn(move |req| {
                let dav_server = dav_server.clone();
                async move {
                    // Simple Route: If GET /, serve HTML UI. Else, WebDAV.
                    if req.method() == Method::GET && req.uri().path() == "/" {
                        return Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                            .header("Content-Type", "text/html")
                            .body(Body::from(Bytes::from(web_assets::HTML)))
                            .unwrap()
                        );
                    }
                    if req.method() == Method::GET && req.uri().path() == "/__metrics" {
                        return Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                            .header("Content-Type", "application/json")
                            .body(Body::from(Bytes::from(url_metrics_json())))
                            .unwrap()
                        );
                    }
                    Ok::<_, std::convert::Infallible>(dav_server.handle(req).await)
                }
            });

            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
                {
                    eprintln!("Error serving connection: {:?}", err);
                }
        });
    }
}
