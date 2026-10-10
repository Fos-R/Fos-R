use nix;
use std::borrow::Cow;
use std::fs::File;
use std::sync::Mutex;
use std::time::Duration;

use crate::{cmd, run};
use fosr_lib::models;

use rouille::{Response, ResponseBody, router, try_or_400};
use serde::Deserialize;

pub fn start(
    port: u16,
    maximum_duration: Option<Duration>,
    base_model: models::Models,
    jobs: Option<usize>,
) -> Result<(), String> {
    #[derive(Deserialize)]
    struct Json {
        // TODO
    }

    let address = format!("localhost:{port}");
    log::info!("Listening on {address}");

    // let base_model: models::ArcModels = model.into();
    // Only one client can generate at the same time
    // This is to avoid DoS attacks
    let mutex = Mutex::new(());

    rouille::start_server(address, move |request| {
        router!(request,
            // A POST route to generate pcap
            (POST) (/generate) => {
                let data: Json = try_or_400!(rouille::input::json_input(request));


                let (raw_read, raw_write) = nix::unistd::pipe().expect("Échec pipe système");
                let _lock = mutex.lock().unwrap(); // Only one generation at a time
                let mut m = base_model.clone();
                let reader = File::from(raw_read);
                let writer = File::from(raw_write);
                let result = m.with_string_network("todo..."); // FIXME: read from request

                if let Err(string) = result {
                    return Response::text(string)
                            .with_status_code(400); // Bad request error
                }
                let result = crate::generate_pcap(
                    "1h".to_string(), // FIXME: read from request
                    None,  // FIXME
                    run::ExportParams{ outfile: run::ExportDestination::Writer(writer), order_pcap: false}, // writer
                    cmd::GenerationProfile::Efficient,
                    None, // FIXME
                    None, // FIXME
                    None, // FIXME
                    jobs,
                    false,
                    m.into());

                match result {
                    Ok(()) => {

                        Response {
                            status_code: 200,
                            headers: vec![
                                (Cow::Borrowed("Content-Type"), Cow::Borrowed("application/octet-stream"))
                            ],
                            data: ResponseBody::from_reader(reader),
                            upgrade: None,
                        }
                    },
                    Err(string) =>
                        Response::text(string)
                            .with_status_code(400) // Bad request error
                }
            },
            // Unknown route
            _ => Response::empty_404()
        )
    });
}
