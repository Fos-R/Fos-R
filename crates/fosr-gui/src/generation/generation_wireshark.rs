/// Opens the PCAP data in Wireshark.
///
/// This creates a temporary file with `.pcap` extension and opens it in Wireshark.
/// The `NamedTempFile` handle and `JoinHandle` are stored to keep the file alive.
/// When the handle is dropped (app closed), the temp file is deleted.
///
/// Platform-specific behavior:
/// - **Linux**: Uses `open::with_in_background()` which spawns Wireshark directly.
///   The thread stays alive while Wireshark is running.
/// - **macOS**: Uses `open -n -W -a Wireshark` which waits for the app to close.
#[cfg(not(target_arch = "wasm32"))]
pub fn open_in_wireshark(
    pcap_bytes: &[u8],
    temp_files: &mut Vec<(
        std::thread::JoinHandle<std::io::Result<()>>,
        tempfile::NamedTempFile,
    )>,
) -> Result<(), String> {
    use std::io::Write;

    // Create a temporary file with .pcap extension
    let mut temp_file = tempfile::Builder::new()
        .suffix(".pcap")
        .tempfile()
        .map_err(|e| format!("Failed to create temp file: {e}"))?;

    // Write the PCAP data
    temp_file
        .write_all(pcap_bytes)
        .map_err(|e| format!("Failed to write PCAP data: {e}"))?;

    // Get the path
    let path = temp_file.path().to_path_buf();

    log::info!("Opening PCAP file in Wireshark: {}", path.display());

    // Platform-specific launch
    #[cfg(target_os = "macos")]
    let handle = {
        // On macOS, use `open -n -W -a Wireshark`:
        // - `-n` opens a new instance even if one is already running
        // - `-W` waits for the app to close
        std::thread::spawn(move || {
            std::process::Command::new("open")
                .args(["-n", "-W", "-a", "Wireshark"])
                .arg(&path)
                .status()
                .map(|_| ())
        })
    };

    #[cfg(not(target_os = "macos"))]
    let handle = open::with_in_background(&path, "wireshark");

    // Store the handle and temp file to keep them alive until app closes
    temp_files.push((handle, temp_file));

    Ok(())
}
