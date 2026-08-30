//! Randomize the Wi-Fi MAC address through the privileged helper.
//!
//! Clean-room: no code from any third-party project appears in this file.
//! term7's "MacOS-Privacy-and-Security-Enhancements" `04_SpoofMAC` is prior art
//! for the idea and is credited as such, but its approach is deliberately *not*
//! reproduced: their LaunchDaemon runs `spoof randomize en0`, and the `spoof`
//! tool only forces the locally-administered bit when it is passed `--local`.
//! Without that flag it draws an address out of a real vendor OUI range —
//! commonly VMware/Xen/Parallels — so the Mac announces "I am a virtual
//! machine" to every network it touches. OnionGate instead asks the privileged
//! helper for `MacRandomize`, which draws six CSPRNG bytes, forces the
//! locally-administered bit on and the multicast bit off, and verifies the
//! address actually stuck. There is no fallback path that bypasses it.

use std::process::Command;

#[derive(Debug, Clone)]
pub struct MacStatus {
    pub device: Option<String>,
    /// Whether the address currently on the card is locally administered, i.e.
    /// randomized rather than the factory vendor address.
    pub locally_administered: Option<bool>,
    pub detail: String,
}

fn run_out(bin: &str, args: &[&str]) -> String {
    Command::new(bin)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// The `ether` line of `ifconfig <device>`.
pub fn parse_ether(ifconfig: &str) -> Option<String> {
    ifconfig
        .lines()
        .find_map(|line| line.trim().strip_prefix("ether "))
        .map(|mac| mac.trim().to_ascii_lowercase())
}

/// Bit 1 of the first octet marks a locally-administered address; bit 0 marks a
/// group address, which is never a valid station address.
pub fn is_locally_administered(mac: &str) -> Option<bool> {
    let first = mac.split(':').next()?;
    let byte = u8::from_str_radix(first, 16).ok()?;
    if mac.split(':').count() != 6 {
        return None;
    }
    Some(byte & 0b0000_0010 != 0 && byte & 0b0000_0001 == 0)
}

pub fn status() -> MacStatus {
    let device = super::wifi_boot::wifi_device();
    let helper_available = crate::helper::client::available();
    // Read the address that is on the card right now; never remember one.
    let locally_administered = device
        .as_deref()
        .map(|dev| run_out("/sbin/ifconfig", &[dev]))
        .as_deref()
        .and_then(parse_ether)
        .as_deref()
        .and_then(is_locally_administered);

    let mut detail = match (&device, locally_administered) {
        (None, _) => "No Wi-Fi device on this Mac".to_string(),
        (Some(dev), Some(true)) => {
            format!("{dev} is using a locally administered (randomized) address")
        }
        (Some(dev), Some(false)) => format!("{dev} is using its factory vendor address"),
        (Some(dev), None) => format!("Could not read the current address of {dev}"),
    };
    if !helper_available {
        detail.push_str(" · needs the privileged helper");
    }
    MacStatus {
        device,
        locally_administered,
        detail,
    }
}

/// One-shot randomization. The address itself never reaches the log or the
/// returned message: it is a hardware identifier, and app logs are exportable.
pub async fn randomize() -> Result<String, String> {
    if super::wifi_boot::wifi_device().is_none() {
        return Err("This Mac has no Wi-Fi device to randomize".into());
    }
    if !crate::helper::client::available() {
        return Err(
            "The privileged helper is not running. OnionGate will not fall back to a script that assigns a real vendor address — install the helper and try again."
                .into(),
        );
    }
    let response = tokio::task::spawn_blocking(|| {
        crate::helper::client::request(&crate::helper::HelperRequest::MacRandomize)
    })
    .await
    .map_err(|e| format!("task join error: {e}"))?
    .map_err(|e| format!("The privileged helper did not answer: {e}"))?;
    if !response.ok {
        return Err(response.message);
    }
    crate::logs::append("Hardening: Wi-Fi MAC address randomized");
    Ok(
        "Wi-Fi MAC randomized (locally administered address). The radio cycled, so reconnect to your network — and re-authenticate if it uses a captive portal or 802.1X."
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ether_line_is_read_out_of_ifconfig() {
        let out = "\
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	options=6460<TSO4,TSO6,CHANNEL_IO>
	ether 02:AB:CD:11:22:33
	inet6 fe80::1%en0 prefixlen 64 secured scopeid 0xc
";
        assert_eq!(parse_ether(out).as_deref(), Some("02:ab:cd:11:22:33"));
        assert_eq!(parse_ether("en0: flags=8863"), None);
    }

    /// A vendor OUI must never read as randomized — that is exactly the failure
    /// mode of the `spoof` tool this item exists to avoid.
    #[test]
    fn only_locally_administered_unicast_addresses_count_as_randomized() {
        assert_eq!(is_locally_administered("02:ab:cd:11:22:33"), Some(true));
        // 00:50:56 is VMware, 00:16:3e is Xen: real vendor space.
        assert_eq!(is_locally_administered("00:50:56:11:22:33"), Some(false));
        assert_eq!(is_locally_administered("00:16:3e:11:22:33"), Some(false));
        // Multicast bit set: not a station address at all.
        assert_eq!(is_locally_administered("03:ab:cd:11:22:33"), Some(false));
        assert_eq!(is_locally_administered("not-a-mac"), None);
        assert_eq!(is_locally_administered("02:ab:cd"), None);
    }
}
