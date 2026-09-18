//! Network interfaces, in the shape `/control/install/get_addresses` returns.
//!
//! The setup wizard is the main caller -- `/control/status` uses
//! [`addresses`] to expand a wildcard listen address: it lists the addresses
//! the admin
//! interface and the DNS server will answer on, and fills the two "Listen
//! interface" dropdowns.  It reads `name`, `ip_addresses` and `flags`, and
//! greys out any interface whose flags do not contain `up`.  Reporting an
//! empty map — which is what this used to do — leaves the wizard with nothing
//! to show and no address to point a router at.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::Serialize;

/// One interface, as Go's `aghnet.NetInterface` marshals it.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct NetInterface {
    /// The MAC address, or empty where the interface has none.
    pub hardware_address: String,
    /// Go's `net.Flags.String()`: the set flags joined with `|`.
    pub flags: String,
    /// Every address configured on the interface.
    pub ip_addresses: Vec<IpAddr>,
    /// The interface's name, repeated here as Go repeats it.
    pub name: String,
    /// The link MTU, or 0 where it could not be read.
    pub mtu: u32,
}

/// Every interface that has at least one address, keyed by name.
///
/// Upstream's `GetValidNetInterfacesForWeb` discards interfaces with no
/// addresses and keeps everything else, loopback included.  The map is sorted
/// so the wizard's dropdown does not reshuffle between loads; Go's map
/// ordering is arbitrary, and nothing depends on it.
pub fn all() -> BTreeMap<String, NetInterface> {
    let Ok(found) = if_addrs::get_if_addrs() else {
        return BTreeMap::new();
    };

    let mut out: BTreeMap<String, NetInterface> = BTreeMap::new();
    for iface in found {
        let entry = out
            .entry(iface.name.clone())
            .or_insert_with(|| NetInterface {
                hardware_address: hardware_address(&iface.name),
                flags: flags(&iface),
                ip_addresses: Vec::new(),
                name: iface.name.clone(),
                mtu: mtu(&iface.name),
            });

        let ip = iface.addr.ip();
        if !entry.ip_addresses.contains(&ip) {
            entry.ip_addresses.push(ip);
        }
    }

    out
}

/// Every address configured on any interface.
///
/// Separate from [`all`] because `/control/status` is polled every ten
/// seconds and needs nothing but the addresses: `all` reads two
/// `/sys/class/net` files per interface for the MAC and the MTU, which only
/// the setup wizard ever looks at.
pub fn addresses() -> Vec<IpAddr> {
    let Ok(found) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };

    let mut out: Vec<IpAddr> = Vec::new();
    for iface in found {
        let ip = iface.addr.ip();
        if !out.contains(&ip) {
            out.push(ip);
        }
    }

    out
}

/// Renders the flags Go would, in Go's own order.
///
/// `net.Flags.String()` walks a fixed table — up, broadcast, loopback,
/// pointtopoint, multicast — and joins what is set with `|`.  Only the three
/// this can determine portably are reported; `broadcast` and `multicast` are
/// not exposed by the enumeration and nothing reads them.
fn flags(iface: &if_addrs::Interface) -> String {
    let mut set = Vec::new();
    if iface.is_oper_up() {
        set.push("up");
    }
    if iface.is_loopback() {
        set.push("loopback");
    }
    if iface.is_p2p() {
        set.push("pointtopoint");
    }

    set.join("|")
}

/// Reads an interface's MAC address, where the OS exposes one.
fn hardware_address(name: &str) -> String {
    sysfs(name, "address")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Reads an interface's MTU, where the OS exposes one.
fn mtu(name: &str) -> u32 {
    sysfs(name, "mtu")
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Reads one `/sys/class/net` attribute.
///
/// Linux only, which is where the Docker image runs and therefore where these
/// two fields are worth having.  Everywhere else they come back empty and
/// zero — the wizard reads neither, and Go reports an empty MAC for an
/// interface without one too.
#[cfg(target_os = "linux")]
fn sysfs(name: &str, attr: &str) -> Option<String> {
    // The name comes from the kernel's own interface list, but it still
    // reaches the filesystem, so refuse anything that could climb out.
    if name.is_empty() || name.contains(['/', '\\']) || name.starts_with('.') {
        return None;
    }

    std::fs::read_to_string(format!("/sys/class/net/{name}/{attr}")).ok()
}

/// Reads one interface attribute: nothing outside Linux.
#[cfg(not(target_os = "linux"))]
fn sysfs(_name: &str, _attr: &str) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_reports_at_least_a_loopback() {
        // The regression this guards is an empty map, which left the setup
        // wizard with no address to show and no interface to choose.
        let ifaces = all();
        assert!(!ifaces.is_empty(), "no interfaces enumerated at all");

        assert!(
            ifaces
                .values()
                .any(|i| i.ip_addresses.iter().any(IpAddr::is_loopback)),
            "no loopback address among {:?}",
            ifaces.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn every_reported_interface_has_an_address_and_a_name() {
        // Upstream discards interfaces with no addresses; the wizard skips
        // them too, and an entry with none would just be noise.
        for (key, iface) in all() {
            assert_eq!(key, iface.name);
            assert!(!iface.ip_addresses.is_empty(), "{key} has no address");
        }
    }

    #[test]
    fn the_cheap_address_list_agrees_with_the_full_one() {
        // Two enumerations of the same thing drift apart silently; the only
        // thing keeping them together is this.
        let mut cheap = addresses();
        let mut full: Vec<IpAddr> = all().into_values().flat_map(|i| i.ip_addresses).collect();
        cheap.sort();
        cheap.dedup();
        full.sort();
        full.dedup();

        assert_eq!(cheap, full);
    }

    #[test]
    fn flags_render_the_way_gos_stringer_does() {
        // The wizard greys out anything whose flags lack "up", so an
        // interface that is up must say so, joined with Go's separator.
        let ifaces = all();
        let loopback = ifaces
            .values()
            .find(|i| i.ip_addresses.iter().any(IpAddr::is_loopback))
            .expect("a loopback interface");

        assert!(
            loopback.flags.contains("loopback"),
            "flags were {:?}",
            loopback.flags
        );
        for part in loopback.flags.split('|') {
            assert!(
                matches!(part, "up" | "loopback" | "pointtopoint"),
                "unexpected flag {part:?}"
            );
        }
    }
}
