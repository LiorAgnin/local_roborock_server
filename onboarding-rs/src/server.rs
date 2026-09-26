//! Server address normalization, onboarding defaults and timezone tables.

use std::fmt;

pub const DEFAULT_COUNTRY_DOMAIN: &str = "us";
pub const DEFAULT_TIMEZONE: &str = "America/New_York";
pub const DEFAULT_CST: &str = "EST5EDT,M3.2.0,M11.1.0";
pub const DEFAULT_STACK_HTTPS_PORT: u16 = 555;
/// The vacuum firmware rejects a `token.r` longer than this.
pub const MAX_STACK_SERVER_LENGTH: usize = 32;

/// IANA timezone -> (POSIX TZ string, country domain) for the vacuum firmware.
const TIMEZONES: &[(&str, &str, &str)] = &[
    ("America/New_York", "EST5EDT,M3.2.0,M11.1.0", "us"),
    ("America/Chicago", "CST6CDT,M3.2.0,M11.1.0", "us"),
    ("America/Denver", "MST7MDT,M3.2.0,M11.1.0", "us"),
    ("America/Los_Angeles", "PST8PDT,M3.2.0,M11.1.0", "us"),
    ("America/Phoenix", "MST7", "us"),
    ("America/Anchorage", "AKST9AKDT,M3.2.0,M11.1.0", "us"),
    ("Pacific/Honolulu", "HST10", "us"),
    ("America/Toronto", "EST5EDT,M3.2.0,M11.1.0", "us"),
    ("America/Vancouver", "PST8PDT,M3.2.0,M11.1.0", "us"),
    ("America/Winnipeg", "CST6CDT,M3.2.0,M11.1.0", "us"),
    ("America/Edmonton", "MST7MDT,M3.2.0,M11.1.0", "us"),
    ("Europe/London", "GMT0BST,M3.5.0/1,M10.5.0", "gb"),
    ("Europe/Berlin", "CET-1CEST,M3.5.0,M10.5.0/3", "de"),
    ("Europe/Paris", "CET-1CEST,M3.5.0,M10.5.0/3", "fr"),
    ("Europe/Amsterdam", "CET-1CEST,M3.5.0,M10.5.0/3", "nl"),
    ("Asia/Shanghai", "CST-8", "cn"),
    ("Asia/Tokyo", "JST-9", "jp"),
    ("Asia/Kolkata", "IST-5:30", "in"),
    ("Australia/Sydney", "AEST-10AEDT,M10.1.0,M4.1.0/3", "au"),
    ("Australia/Melbourne", "AEST-10AEDT,M10.1.0,M4.1.0/3", "au"),
    ("Australia/Perth", "AWST-8", "au"),
];

/// POSIX TZ string for an IANA timezone, or `""` if unknown.
pub fn posix_tz_from_iana(iana: &str) -> &'static str {
    lookup(iana).map_or("", |(_, posix, _)| posix)
}

/// Country domain for an IANA timezone, or `""` if unknown.
pub fn country_from_iana(iana: &str) -> &'static str {
    lookup(iana).map_or("", |(_, _, country)| country)
}

fn lookup(iana: &str) -> Option<&'static (&'static str, &'static str, &'static str)> {
    let iana = iana.trim();
    TIMEZONES.iter().find(|(name, _, _)| *name == iana)
}

/// Known IANA timezones, sorted (the GUI's timezone dropdown).
pub fn known_timezones() -> Vec<&'static str> {
    let mut zones: Vec<&str> = TIMEZONES.iter().map(|(name, _, _)| *name).collect();
    zones.sort_unstable();
    zones
}

/// A server address the user typed could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidServer(pub String);

impl fmt::Display for InvalidServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InvalidServer {}

/// `https://api-<host>[:port]` admin API base URL; the port defaults to 555
/// and is omitted when it is 443.
pub fn normalize_api_base_url(server: &str) -> Result<String, InvalidServer> {
    let (host, port) = parse_server_target(server, DEFAULT_STACK_HTTPS_PORT)?;
    let host = if has_api_prefix(&host) {
        host
    } else {
        format!("api-{host}")
    };
    Ok(format!("https://{}", format_authority(&host, port, 443)))
}

/// The `token.r` value sent to the vacuum: `<host without api->[:port]/`,
/// at most 32 characters.
pub fn sanitize_stack_server(server: &str) -> Result<String, InvalidServer> {
    let (host, port) = parse_server_target(server, DEFAULT_STACK_HTTPS_PORT)?;
    let host = if has_api_prefix(&host) {
        &host[4..]
    } else {
        &host[..]
    };
    let authority = format_authority(host, port, 443);
    if authority.is_empty() {
        return Err(host_required());
    }
    let stack_server = format!("{authority}/");
    let len = stack_server.chars().count();
    if len > MAX_STACK_SERVER_LENGTH {
        return Err(InvalidServer(format!(
            "Server host is too long for onboarding: token.r must be at most \
             {MAX_STACK_SERVER_LENGTH} characters, got {len} ({stack_server})."
        )));
    }
    Ok(stack_server)
}

fn has_api_prefix(host: &str) -> bool {
    host.get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("api-"))
}

fn host_required() -> InvalidServer {
    InvalidServer("A server host is required.".into())
}

fn port_not_numeric() -> InvalidServer {
    InvalidServer("Server port must be numeric.".into())
}

/// Host and port of a user-entered server, following Python's
/// `urllib.parse.urlsplit(...).hostname` / `.port` rules: the hostname is
/// lowercased, userinfo is dropped and the port must be 0-65535.
fn parse_server_target(server: &str, default_port: u16) -> Result<(String, u16), InvalidServer> {
    let value = server.trim();
    if value.is_empty() {
        return Err(host_required());
    }
    let after_scheme = value.split_once("://").map_or(value, |(_, rest)| rest);
    let netloc = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let hostinfo = netloc.rsplit_once('@').map_or(netloc, |(_, host)| host);
    let (host, port) = match hostinfo.strip_prefix('[') {
        Some(bracketed) => {
            let (host, rest) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            (host, rest.split_once(':').map_or("", |(_, port)| port))
        }
        None => hostinfo.split_once(':').unwrap_or((hostinfo, "")),
    };
    let host = host.to_lowercase();
    let host = host.trim().trim_matches('/');
    if host.is_empty() {
        return Err(host_required());
    }
    let port = if port.is_empty() {
        default_port
    } else if port.bytes().all(|b| b.is_ascii_digit()) {
        port.parse::<u16>().map_err(|_| port_not_numeric())?
    } else {
        return Err(port_not_numeric());
    };
    Ok((host.to_owned(), port))
}

fn format_authority(host: &str, port: u16, default_port: u16) -> String {
    let host = host.trim().trim_matches('/');
    if host.is_empty() || port == default_port {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    }
}

/// Everything one onboarding run needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnboardingConfig {
    pub api_base_url: String,
    pub stack_server: String,
    pub admin_password: String,
    pub ssid: String,
    pub password: String,
    pub timezone: String,
    pub cst: String,
    pub country_domain: String,
    pub allow_insecure_tls: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(msg: &str) -> InvalidServer {
        InvalidServer(msg.into())
    }

    #[test]
    fn normalization_preserves_custom_ports() {
        assert_eq!(
            normalize_api_base_url("api-roborock.example.com:8443").unwrap(),
            "https://api-roborock.example.com:8443"
        );
        assert_eq!(
            sanitize_stack_server("https://api-roborock.example.com:8443").unwrap(),
            "roborock.example.com:8443/"
        );
    }

    #[test]
    fn normalization_defaults_to_port_555() {
        assert_eq!(
            normalize_api_base_url("api-roborock.example.com").unwrap(),
            "https://api-roborock.example.com:555"
        );
        assert_eq!(
            sanitize_stack_server("https://api-roborock.example.com").unwrap(),
            "roborock.example.com:555/"
        );
    }

    #[test]
    fn normalization_adds_api_prefix_and_strips_trailing_slash() {
        assert_eq!(
            normalize_api_base_url("https://roborock.example.com:8443/").unwrap(),
            "https://api-roborock.example.com:8443"
        );
        assert_eq!(
            sanitize_stack_server("https://roborock.example.com:8443/").unwrap(),
            "roborock.example.com:8443/"
        );
    }

    #[test]
    fn port_443_is_omitted() {
        assert_eq!(
            normalize_api_base_url("roborock.example.com:443").unwrap(),
            "https://api-roborock.example.com"
        );
        assert_eq!(
            sanitize_stack_server("roborock.example.com:443").unwrap(),
            "roborock.example.com/"
        );
    }

    #[test]
    fn rejects_non_numeric_or_out_of_range_port() {
        for server in [
            "api-roborock.example.com:not-a-port",
            "a.example.com:70000",
            "a.b:1:2",
        ] {
            assert_eq!(
                normalize_api_base_url(server),
                Err(err("Server port must be numeric.")),
                "{server}"
            );
        }
    }

    #[test]
    fn rejects_missing_host() {
        for server in ["", "   ", "https://", ":555", "user@"] {
            assert_eq!(
                sanitize_stack_server(server),
                Err(err("A server host is required.")),
                "{server:?}"
            );
        }
    }

    #[test]
    fn enforces_32_char_token_r_limit() {
        assert_eq!(
            sanitize_stack_server("abcdefghijklmno.example.com:555").unwrap(),
            "abcdefghijklmno.example.com:555/"
        );
        assert_eq!(
            sanitize_stack_server("abcdefghijklmnop.example.com:555"),
            Err(err(
                "Server host is too long for onboarding: token.r must be at most 32 characters, \
                 got 33 (abcdefghijklmnop.example.com:555/)."
            ))
        );
    }

    #[test]
    fn host_is_lowercased_and_userinfo_dropped() {
        assert_eq!(
            normalize_api_base_url("user:pw@API-Roborock.Example.COM").unwrap(),
            "https://api-roborock.example.com:555"
        );
    }

    #[test]
    fn timezone_lookups() {
        assert_eq!(
            posix_tz_from_iana(" Europe/Berlin "),
            "CET-1CEST,M3.5.0,M10.5.0/3"
        );
        assert_eq!(country_from_iana("Asia/Tokyo"), "jp");
        assert_eq!(posix_tz_from_iana("Mars/Olympus"), "");
        assert_eq!(country_from_iana("Mars/Olympus"), "");
        assert_eq!(posix_tz_from_iana(DEFAULT_TIMEZONE), DEFAULT_CST);
    }

    #[test]
    fn known_timezones_are_sorted() {
        let zones = known_timezones();
        assert_eq!(zones.len(), 21);
        assert_eq!(zones.first(), Some(&"America/Anchorage"));
        assert!(zones.windows(2).all(|w| w[0] < w[1]));
    }
}
