use std::borrow::Cow;
use std::cmp::max;
use std::io::Read;
use std::io::pipe;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use crate::run;
use fosr_lib::inject;
use fosr_lib::models;
use fosr_lib::stage1;
use fosr_lib::stage2;
use fosr_lib::stage3;
use fosr_lib::stage4;
use fosr_lib::stats;

use base64::prelude::*;
use rouille::input::json::JsonError;
use rouille::{Response, ResponseBody, try_or_400};
use serde::Deserialize;

pub fn json_input<O>(request: &rouille::Request) -> Result<O, JsonError>
where
    O: serde::de::DeserializeOwned,
{
    if let Some(header) = request.header("Content-Type") {
        if !header.starts_with("application/json") {
            return Err(JsonError::WrongContentType);
        }
    } else {
        return Err(JsonError::WrongContentType);
    }

    if let Some(mut b) = request.data() {
        if let Some(length) = request.header("Content-Length") {
            let length = usize::from_str(length).map_err(|_| JsonError::WrongContentType)?;
            let mut buf = vec![0; length];
            b.read_exact(&mut buf)?;
            serde_json::from_slice(&buf).map_err(From::from)
        } else {
            serde_json::from_reader::<_, O>(b).map_err(From::from)
        }
    } else {
        Err(JsonError::BodyAlreadyExtracted)
    }
}

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

    let jobs = jobs.unwrap_or(max(1, num_cpus::get() / 2));

    let (s2_count, s3_count, s4_count) = (
        max(1, jobs / 3),
        max(1, jobs / 3),
        max(1, jobs - 2 * (jobs / 3)),
    );

    // Only one client can generate at the same time
    // This is to avoid DoS attacks
    let mutex = Arc::new(Mutex::new(()));

    // Only one connection at a time (with is complementary to the mutex)
    rouille::start_server_with_pool(address, Some(1), move |request| {
        dbg!(request.method());
        dbg!(request.url());
        if request.url() == "/pcap" {
            // any method works
            dbg!(&request);
            let data: JsonRequest = try_or_400!(json_input(request));

            let (reader, writer) = try_or_400!(pipe());
            let mut model = base_model.clone();
            let network = try_or_400!(BASE64_STANDARD.decode(data.network));
            let network = try_or_400!(String::from_utf8(network));
            model = try_or_400!(
                model
                    .with_string_network(&network)
                    .map_err(std::io::Error::other)
            );
            let model: models::ArcModels = model.into();
            let duration =
                try_or_400!(humantime::parse_duration(&data.duration)).min(maximum_duration);
            let export = run::ExportParams {
                outfile: run::ExportDestination::Writer(writer),
                order_pcap: false,
            }; // write to pipe writer
            let target = stats::Target::GenerationDuration(duration);

            if let Some(s) = data.seed {
                log::info!("Generating with seed {s}");
            }

            let (initial_ts, tz_offset) = try_or_400!(
                crate::get_start_time_and_offset(data.start_time, data.tz)
                    .map_err(std::io::Error::other)
            );

            let s1 = stage1::BinBasedGenerator::new(
                data.seed,
                false,
                None,
                model.time_bins,
                initial_ts,
                Some(duration),
                tz_offset,
            );
            let s2 = stage2::bn_generator::BNGenerator::new(model.bn, false);
            let s3 = stage3::tadam::TadamGenerator::new(model.automata);
            let s4 = stage4::Stage4::new(false);

            let mutex = mutex.clone();
            let builder = thread::Builder::new().name("fosr-generation".into());

            // we do not use the ThreadHandle to detach the thread
            let _detached_thread = builder.spawn(move || {
                let lock = mutex.lock().unwrap(); // Only one generation at a time
                let result = run::run_efficient(
                    vec![],
                    Some(export),
                    s1,
                    (s2, s2_count),
                    (s3, s3_count),
                    (s4, s4_count),
                    Arc::new(stats::Stats::new(target)),
                    None::<run::InjectParam<inject::DummyNetEnabler>>,
                    false,
                );

                // If there is an error in the thread, it’s too late to send a 400 Error
                if let Err(s) = result {
                    log::warn!("Generation stopped early: {s}");
                }

                // move the lock to the thread and unlock at the end of the generation
                drop(lock);
            });

            // Send the file as a stream
            rouille::content_encoding::apply(
                request,
                Response {
                    status_code: 200,
                    headers: vec![(
                        Cow::Borrowed("Content-Type"),
                        Cow::Borrowed("application/octet-stream"),
                    )],
                    data: ResponseBody::from_reader(reader),
                    upgrade: None,
                },
            )
        } else {
            // Unknown route
            Response::empty_404()
        }
    });
}
