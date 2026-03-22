use super::generation_validation::FieldValidation;
use chrono::{Local, NaiveDate, NaiveTime};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Receiver;
use std::time::Duration;

// Time interval for the slider.
pub const DURATION_MIN: Duration = Duration::from_secs(60); // 1 min
#[cfg(not(target_arch = "wasm32"))]
pub const DURATION_MAX: Duration = Duration::from_secs(3 * 24 * 3600); // 3 days
#[cfg(target_arch = "wasm32")]
pub const DURATION_MAX: Duration = Duration::from_secs(24 * 3600); // 1 day (browser tab memory is limited)

/// Represents the state of the generation tab.
pub struct GenerationTabState {
    pub progress: f32,
    pub progress_receiver: Option<Receiver<f32>>,
    pub pcap_bytes: Option<Vec<u8>>,
    pub pcap_receiver: Option<Receiver<Vec<u8>>>,
    pub throughput_receiver: Option<Receiver<String>>,
    pub throughput: Option<String>,
    pub cancelled: Arc<AtomicBool>,
    /// Error message to display, if any
    pub error: Option<String>,
    // Validation states
    pub duration_validation: FieldValidation,
    pub seed_validation: FieldValidation,
    pub timezone_validation: FieldValidation,
    // Parameters
    pub order_pcap: bool,
    pub taint: bool,
    pub duration_str: String,
    pub use_seed: bool,
    pub seed_input: String,
    pub timezone_input: String,
    pub use_current_time: bool,
    pub use_local_timezone: bool,
    pub start_date: NaiveDate,
    pub start_hour: NaiveTime,
    pub output_file_name: String,
    /// Holds temporary PCAP files opened in Wireshark along with their background thread handles.
    ///
    /// `NamedTempFile` automatically deletes the file when dropped. By storing them here,
    /// the files stay alive until the app closes. Multiple files can be open simultaneously
    /// for comparison purposes.
    ///
    /// The `JoinHandle` comes from `open::with_in_background()`. The thread stays alive while
    /// Wireshark is running, so `is_finished()` can detect active sessions.
    #[cfg(not(target_arch = "wasm32"))]
    pub temp_pcap_files: Vec<(
        std::thread::JoinHandle<std::io::Result<()>>,
        tempfile::NamedTempFile,
    )>,
    /// Whether Wireshark is available on the system
    #[cfg(not(target_arch = "wasm32"))]
    pub wireshark_available: bool,
}

impl GenerationTabState {
    /// Returns true if generation is currently in progress
    pub fn is_generating(&self) -> bool {
        self.progress_receiver.is_some()
    }

    /// Returns true if generation is complete (PCAP ready)
    pub fn is_complete(&self) -> bool {
        self.progress == 1.0
    }
}

impl Default for GenerationTabState {
    fn default() -> Self {
        Self {
            progress: 0.0,
            progress_receiver: None,
            pcap_bytes: None,
            pcap_receiver: None,
            throughput_receiver: None,
            throughput: None,
            cancelled: Arc::new(AtomicBool::new(false)),
            error: None,
            // Validation states
            duration_validation: FieldValidation::default(),
            seed_validation: FieldValidation::default(),
            timezone_validation: FieldValidation::default(),
            // Parameters
            order_pcap: true,
            taint: false,
            duration_str: "1h".to_string(),
            use_seed: false,
            seed_input: String::new(),
            timezone_input: String::new(),
            use_current_time: true,
            use_local_timezone: true,
            start_date: Local::now().date_naive(),
            start_hour: Local::now().time(),
            output_file_name: "output.pcap".to_string(),
            #[cfg(not(target_arch = "wasm32"))]
            temp_pcap_files: Vec::new(),
            #[cfg(not(target_arch = "wasm32"))]
            wireshark_available: which::which("wireshark").is_ok(),
        }
    }
}
