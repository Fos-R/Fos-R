pub(crate) fn duration_to_timeval(duration: std::time::Duration) -> libc::timeval {
    libc::timeval {
        tv_sec: duration.as_secs() as libc::time_t,
        tv_usec: duration.subsec_micros() as libc::suseconds_t,
    }
}

pub(crate) fn timeval_to_duration(timeval: libc::timeval) -> std::time::Duration {
    std::time::Duration::new(timeval.tv_sec as u64, (timeval.tv_usec * 1000) as u32)
}
