use std::io;

use crate::install_model::InstallRecord;
use crate::installer::{conflict, inspect_install_record, invalid_data, verify_active};
use crate::lifecycle_contract::Operation;
use crate::socket_preflight::{SocketReservation, reserve_available};

pub(crate) fn prepare_authority(
    operation: Operation,
    existing_reservation: Option<SocketReservation>,
) -> io::Result<(Option<InstallRecord>, Option<SocketReservation>)> {
    let record = inspect_install_record()?;
    require_mode(record.as_ref(), operation)?;
    let reservation = if let Some(value) = &record {
        if existing_reservation.is_some() {
            return Err(conflict(
                "the listener reservation no longer matches a fresh installation",
            ));
        }
        verify_active(value)?;
        None
    } else {
        require_publications_absent()?;
        crate::installer::require_generation_roots_absent()?;
        crate::system_publication::validate_unit_publication_directories()?;
        Some(match existing_reservation {
            Some(reservation) => reservation,
            None => reserve_available()?,
        })
    };
    Ok((record, reservation))
}

fn require_mode(record: Option<&InstallRecord>, operation: Operation) -> io::Result<()> {
    match (operation, record) {
        (Operation::Install, None) | (Operation::Update, Some(_)) => Ok(()),
        (Operation::Install, Some(_)) => Err(conflict("Remap is already installed")),
        (Operation::Update, None) => Err(conflict("Remap is not installed")),
        (Operation::Uninstall | Operation::Recover, _) => Err(invalid_data("invalid operation")),
    }
}

fn require_publications_absent() -> io::Result<()> {
    for path in crate::lifecycle_contract::publication_paths() {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(_) => return Err(conflict("a public Remap installation path is occupied")),
        }
    }
    Ok(())
}
