use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn timestamp_after(previous: Option<u64>) -> io::Result<(u64, u64)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_error| invalid_data("system clock predates the Unix epoch"))?;
    let wall_generation = u64::try_from(now.as_nanos())
        .map_err(|_error| invalid_data("system clock exceeds the generation range"))?;
    let generation = monotonic_generation(wall_generation, previous)
        .ok_or_else(|| invalid_data("resolver generation counter is exhausted"))?;
    Ok((generation, now.as_secs()))
}

pub(crate) const fn monotonic_generation(
    wall_generation: u64,
    previous: Option<u64>,
) -> Option<u64> {
    match previous {
        Some(previous) => match previous.checked_add(1) {
            Some(next) if next > wall_generation => Some(next),
            Some(_next) => Some(wall_generation),
            None => None,
        },
        None => Some(wall_generation),
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
