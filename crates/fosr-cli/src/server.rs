use std::borrow::Cow;
use std::fs::File;
use std::sync::Mutex;
use std::time::Duration;

use crate::{cmd, run};
use fosr_lib::models;

use nix;
use base64::prelude::*;
use rouille::{Response, ResponseBody, router, try_or_400};
use serde::Deserialize;

pub fn start(
    port: u16,
    maximum_duration: Option<Duration>,
    base_model: models::Models,
    jobs: Option<usize>,
) -> Result<(), String> {
    #[derive(Deserialize, Debug)]
    struct JsonRequest {
        duration: String,
        seed: Option<u64>,
        start_time: Option<String>,
        tz: Option<String>,
        network: String,
    }
    let maximum_duration = maximum_duration.unwrap_or(Duration::MAX);
    let address = format!("localhost:{port}");
    log::info!("Listening on {address}");

    // Only one client can generate at the same time
    // This is to avoid DoS attacks
    let mutex = Mutex::new(());

    rouille::start_server(address, move |request| {
        router!(request,
            // A GET route to generate pcap
            (GET) (/pcap) => {
                let data: JsonRequest = try_or_400!(rouille::input::json_input(request));

                log::info!("Received request: {data:?}");
                let (raw_read, raw_write) = try_or_400!(nix::unistd::pipe());
                let _lock = mutex.lock().unwrap(); // Only one generation at a time
                let mut m = base_model.clone();
                let reader = File::from(raw_read);
                let writer = File::from(raw_write);
                let network = try_or_400!(BASE64_STANDARD.decode(data.network));
                let network = try_or_400!(String::from_utf8(network));
                try_or_400!(m.with_string_network(&network).map_err(|s| std::io::Error::new(std::io::ErrorKind::Other, s)));

                let duration = try_or_400!(humantime::parse_duration(&data.duration)).min(maximum_duration);

                try_or_400!(crate::generate_pcap(
                    duration,
                    data.seed,
                    run::ExportParams { outfile: run::ExportDestination::Writer(writer), order_pcap: false}, // write to pipe writer
                    cmd::GenerationProfile::Efficient,
                    data.start_time,
                    None,
                    data.tz,
                    jobs,
                    false,
                    m.into(),
                    false).map_err(|s| std::io::Error::new(std::io::ErrorKind::Other, s)));

                rouille::content_encoding::apply(request, Response {
                    status_code: 200,
                    headers: vec![
                        (Cow::Borrowed("Content-Type"), Cow::Borrowed("application/octet-stream"))
                    ],
                    data: ResponseBody::from_reader(reader),
                    upgrade: None,
                })
            },
            // Unknown route
            _ => Response::empty_404()
        )
    });
}
