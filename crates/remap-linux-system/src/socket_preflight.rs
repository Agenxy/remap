use std::collections::BTreeMap;
use std::io;
use std::net::{TcpListener, UdpSocket};
use std::os::fd::OwnedFd;

use remap_linux::{DescriptorKind, SocketContract};

#[derive(Debug)]
pub(crate) struct SocketReservation {
    probes: BTreeMap<&'static str, OwnedFd>,
}

pub(crate) fn reserve_available() -> io::Result<SocketReservation> {
    let contract = SocketContract::remap();
    reserve_descriptors(contract.descriptors())
}

pub(crate) fn reserve_units(units: &[&str]) -> io::Result<SocketReservation> {
    let contract = SocketContract::remap();
    let mut descriptors = Vec::with_capacity(units.len());
    for unit in units {
        let name = descriptor_name(unit)?;
        let descriptor = contract
            .descriptors()
            .iter()
            .find(|descriptor| descriptor.name() == name)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the reserved listener unit is outside the socket contract",
                )
            })?;
        descriptors.push(descriptor);
    }
    reserve_descriptors(&descriptors)
}

fn reserve_descriptors<T>(descriptors: &[T]) -> io::Result<SocketReservation>
where
    T: std::borrow::Borrow<remap_linux::DescriptorSpec>,
{
    let mut probes = BTreeMap::new();
    for descriptor in descriptors {
        let descriptor = *descriptor.borrow();
        let probe = bind_one(descriptor.kind(), descriptor.name(), descriptor.address())?;
        if probes.insert(descriptor.name(), probe).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the listener reservation contract contains a duplicate descriptor",
            ));
        }
    }
    Ok(SocketReservation { probes })
}

impl SocketReservation {
    pub(crate) fn covers_unit(&self, unit: &str) -> io::Result<bool> {
        Ok(self.probes.contains_key(descriptor_name(unit)?))
    }

    pub(crate) fn release_unit(&mut self, unit: &str) -> io::Result<()> {
        let name = descriptor_name(unit)?;
        self.probes.remove(name).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "the exact listener reservation is unavailable for handoff",
            )
        })?;
        Ok(())
    }

    pub(crate) fn merge(&mut self, other: Self) -> io::Result<()> {
        if other
            .probes
            .keys()
            .any(|name| self.probes.contains_key(name))
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "the listener handoff attempted to duplicate a reservation",
            ));
        }
        self.probes.extend(other.probes);
        Ok(())
    }
}

pub(crate) fn ensure_unit_reserved(
    reservation: &mut Option<SocketReservation>,
    unit: &'static str,
) -> io::Result<()> {
    ensure_unit_reserved_with(reservation, unit, || reserve_units(&[unit]))
}

fn ensure_unit_reserved_with<F>(
    reservation: &mut Option<SocketReservation>,
    unit: &'static str,
    reserve: F,
) -> io::Result<()>
where
    F: FnOnce() -> io::Result<SocketReservation>,
{
    if reservation
        .as_ref()
        .map(|value| value.covers_unit(unit))
        .transpose()?
        .unwrap_or(false)
    {
        return Ok(());
    }
    let replacement = reserve()?;
    if let Some(current) = reservation {
        current.merge(replacement)
    } else {
        *reservation = Some(replacement);
        Ok(())
    }
}

fn descriptor_name(unit: &str) -> io::Result<&str> {
    unit.strip_prefix("remapd-")
        .and_then(|value| value.strip_suffix(".socket"))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the reserved listener has an invalid systemd unit identity",
            )
        })
}

fn bind_one(kind: DescriptorKind, name: &str, address: &str) -> io::Result<OwnedFd> {
    match kind {
        DescriptorKind::Datagram => UdpSocket::bind(address).map(OwnedFd::from),
        DescriptorKind::Stream => TcpListener::bind(address).map(OwnedFd::from),
    }
    .map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("the required {name} loopback listener at {address} is unavailable: {error}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io;
    use std::net::{TcpListener, UdpSocket};
    use std::os::fd::OwnedFd;

    use remap_linux::DescriptorKind;

    use super::{SocketReservation, bind_one, ensure_unit_reserved_with};

    #[test]
    fn reservation_handoff_releases_and_reacquires_only_one_exact_unit() -> io::Result<()> {
        let descriptor = || {
            TcpListener::bind("127.0.0.1:0")
                .map(OwnedFd::from)
                .map(|descriptor| BTreeMap::from([("dns-tcp", descriptor)]))
                .map(|probes| SocketReservation { probes })
        };
        let mut reservation = descriptor()?;
        assert!(reservation.covers_unit("remapd-dns-tcp.socket")?);
        reservation.release_unit("remapd-dns-tcp.socket")?;
        assert!(!reservation.covers_unit("remapd-dns-tcp.socket")?);
        reservation.merge(descriptor()?)?;
        assert!(reservation.covers_unit("remapd-dns-tcp.socket")?);
        assert!(reservation.merge(descriptor()?).is_err());
        Ok(())
    }

    #[test]
    fn partial_reservation_requires_top_up_for_a_newly_missing_unit() -> io::Result<()> {
        let descriptor = TcpListener::bind("127.0.0.1:0").map(OwnedFd::from)?;
        let mut reservation = Some(SocketReservation {
            probes: BTreeMap::from([("dns-tcp", descriptor)]),
        });
        assert!(!reservation_covers(
            reservation.as_ref(),
            "remapd-http.socket"
        )?);

        ensure_unit_reserved_with(&mut reservation, "remapd-http.socket", || {
            let descriptor = TcpListener::bind("127.0.0.1:0").map(OwnedFd::from)?;
            Ok(SocketReservation {
                probes: BTreeMap::from([("http", descriptor)]),
            })
        })?;
        assert!(reservation_covers(
            reservation.as_ref(),
            "remapd-dns-tcp.socket"
        )?);
        assert!(reservation_covers(
            reservation.as_ref(),
            "remapd-http.socket"
        )?);
        Ok(())
    }

    fn reservation_covers(reservation: Option<&SocketReservation>, unit: &str) -> io::Result<bool> {
        reservation
            .map(|value| value.covers_unit(unit))
            .transpose()
            .map(|covered| covered.unwrap_or(false))
    }

    #[test]
    fn tcp_preflight_refuses_an_occupied_address() -> io::Result<()> {
        let occupant = TcpListener::bind("127.0.0.1:0")?;
        let address = occupant.local_addr()?.to_string();
        let error = match bind_one(DescriptorKind::Stream, "test-tcp", &address) {
            Ok(_probe) => return Err(io::Error::other("the occupied TCP address was accepted")),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert!(error.to_string().contains(&address));
        Ok(())
    }

    #[test]
    fn udp_preflight_refuses_an_occupied_address() -> io::Result<()> {
        let occupant = UdpSocket::bind("127.0.0.1:0")?;
        let address = occupant.local_addr()?.to_string();
        let error = match bind_one(DescriptorKind::Datagram, "test-udp", &address) {
            Ok(_probe) => return Err(io::Error::other("the occupied UDP address was accepted")),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert!(error.to_string().contains(&address));
        Ok(())
    }
}
