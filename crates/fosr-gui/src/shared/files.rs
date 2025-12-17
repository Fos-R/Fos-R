use rfd::FileHandle;
use std::io::Error;

#[cfg(not(target_arch = "wasm32"))]
pub fn show_file_picker_desktop() -> Option<FileHandle> {
    rfd::FileDialog::new()
        .add_filter("Configuration files", &["json", "yaml", "yml"])
        .set_directory(std::env::current_dir().unwrap_or(std::path::PathBuf::from("/")))
        .pick_file()
        .map(|path| FileHandle::from(path))
}

#[cfg(target_arch = "wasm32")]
pub async fn show_file_picker_wasm() -> Option<FileHandle> {
    rfd::AsyncFileDialog::new()
        .add_filter("Configuration files", &["json", "yaml", "yml"])
        .pick_file()
        .await
}

#[cfg(not(target_arch = "wasm32"))]
pub fn read_file_desktop(file_handle: &FileHandle) -> String {
    std::fs::read_to_string(file_handle.path()).unwrap()
}

#[cfg(target_arch = "wasm32")]
pub async fn read_file_wasm(file_handle: &FileHandle) -> String {
    let content = file_handle.read().await;
    String::from_utf8(content).expect("Invalid UTF-8")
}

#[cfg(not(target_arch = "wasm32"))]
pub fn save_file_desktop(data: &[u8], file_name: &str) -> Result<FileHandle, Error> {
    let result = rfd::FileDialog::new()
        .set_directory(std::env::current_dir().unwrap_or(std::path::PathBuf::from("/")))
        .set_file_name(file_name)
        .save_file()
        .map(|path| FileHandle::from(path));

    match result {
        Some(file_handle) => match std::fs::write(file_handle.path(), data) {
            Ok(_) => Ok(file_handle),
            Err(e) => Err(e),
        },
        None => Err(Error::new(std::io::ErrorKind::Other, "No file selected")),
    }
}

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
