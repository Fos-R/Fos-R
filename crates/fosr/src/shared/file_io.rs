//! Cross-platform file I/O: desktop (native) and WASM (async) implementations.

use rfd::FileHandle;
use std::io::Error;

/// Opens a native file picker dialog for selecting a YAML configuration file (desktop only).
#[cfg(not(target_arch = "wasm32"))]
pub fn show_file_picker_desktop() -> Option<FileHandle> {
    rfd::FileDialog::new()
        .add_filter("YAML Configuration files", &["yaml", "yml"])
        .set_directory(std::env::current_dir().unwrap_or(std::path::PathBuf::from("/")))
        .pick_file()
        .map(FileHandle::from)
}

/// Opens an async file picker dialog for selecting a YAML configuration file (WASM only).
#[cfg(target_arch = "wasm32")]
pub async fn show_file_picker_wasm() -> Option<FileHandle> {
    rfd::AsyncFileDialog::new()
        .add_filter("YAML Configuration files", &["yaml", "yml"])
        .pick_file()
        .await
}

/// Reads file content synchronously from the given file handle (desktop only).
#[cfg(not(target_arch = "wasm32"))]
pub fn read_file_desktop(file_handle: &FileHandle) -> Result<String, String> {
    std::fs::read_to_string(file_handle.path())
        .map_err(|e| format!("Failed to read file: {}", e))
}

/// Reads file content asynchronously from the given file handle (WASM only).
#[cfg(target_arch = "wasm32")]
pub async fn read_file_wasm(file_handle: &FileHandle) -> Result<String, String> {
    let content = file_handle.read().await;
    String::from_utf8(content).map_err(|e| format!("Invalid UTF-8 in file: {}", e))
}

/// Opens a save dialog and writes data to the selected file (desktop only).
#[cfg(not(target_arch = "wasm32"))]
pub fn save_file_desktop(data: &[u8], file_name: &str) -> Result<FileHandle, Error> {
    let result = rfd::FileDialog::new()
        .set_directory(std::env::current_dir().unwrap_or(std::path::PathBuf::from("/")))
        .set_file_name(file_name)
        .save_file()
        .map(FileHandle::from);

    match result {
        Some(file_handle) => match std::fs::write(file_handle.path(), data) {
            Ok(_) => Ok(file_handle),
            Err(e) => Err(e),
        },
        None => Err(Error::other("No file selected")),
    }
}

/// Opens a save dialog and writes data to the selected file (WASM only).
#[cfg(target_arch = "wasm32")]
pub async fn save_file_wasm(data: &[u8], file_name: &str) -> Result<FileHandle, Error> {
    let result = rfd::AsyncFileDialog::new()
        .set_file_name(file_name)
        .save_file()
        .await;
    match result {
        Some(file_handle) => match file_handle.write(data).await {
            Ok(_) => Ok(file_handle),
            Err(e) => Err(e),
        },
        None => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "No file selected",
        )),
    }
}
