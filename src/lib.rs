//! Fritz!Box logs parsing library
//!
//! Currently only textual logs could be parsed. To fetch the logs one can use a python module
//! [fritzconnection](https://pypi.python.org/pypi/fritzconnection) from a command line like the
//! following:
//! 
//! ```
//! % python -c "from fritzconnection import FritzConnection; from getpass import getpass; \
//!              conn = FritzConnection(password=getpass()); \
//!              logs = conn.call_action('DeviceInfo:1', 'GetDeviceLog'); \
//!              print(logs['NewDeviceLog'])"
//! ```

extern crate chrono;
#[macro_use]
extern crate lazy_static;
extern crate regex;
#[macro_use]
extern crate serde_derive;

use std::io::{self, BufRead};
use chrono::{DateTime, Local, TimeZone};
use regex::Regex;

/// Bandwitdh information.
#[derive(Ord, PartialOrd, Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
#[derive(Debug)]
pub struct DslBandwidth {
    /// Download bandwidth, kbit/s.
    pub download: u64,
    /// Upload bandwidth, kbit/s.
    pub upload: u64,
}

/// Details about the internet connection.
#[derive(Ord, PartialOrd, Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
#[derive(Debug)]
pub struct InternetDetails {
    /// Ip address.
    pub ip: String,
    /// DNS (usually two of them).
    pub dns: Vec<String>,
    /// Gateway.
    pub gateway: String,
}

/// Kind of a log entry.
#[derive(Ord, PartialOrd, Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
#[derive(Debug)]
pub enum EntryKind {
    /// German: 'DSL antwortet nicht'.
    DslNoAnswer,
    /// German: 'DSL ist verfügbar'.
    DslReady(DslBandwidth),
    /// German: 'Internetverbindung wurde erfolgreich hergestellt'.
    InternetEstablished(InternetDetails),
    /// An entry we don't care about.
    Unknown,
}

/// Log entry.
#[derive(Ord, PartialOrd, Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
#[derive(Debug)]
pub struct Entry {
    /// Entry timestamp (unix epoch).
    pub timestamp: i64,
    /// Original message.
    pub message: String,
    /// Entry details.
    pub details: EntryKind,
}

/// Reads a single line from a buffer and truncates it.
fn get_string<B: BufRead>(buf: &mut B) -> io::Result<Option<String>> {
    let mut line = String::new();
    match buf.read_line(&mut line)? {
        0 => Ok(None),
        _ => Ok(Some(line.trim().to_string())),
    }
}

/// Extracts an entry kind (and its details) from a message.
fn parse_message(msg: &str) -> EntryKind {
    lazy_static! {
        static ref NO_ANSWER: Regex = Regex::new("DSL antwortet nicht \\(Keine \
            DSL-Synchronisierung\\)\\.").unwrap();
        static ref READY: Regex = Regex::new("DSL ist verfügbar \\(DSL-Synchronisierung besteht \
            mit (\\d+)/(\\d+) kbit/s\\).").unwrap();
        static ref INTERNET_OK: Regex = Regex::new("Internetverbindung wurde erfolgreich \
            hergestellt\\. IP-Adresse: ([0-9a-fA-F\\.:]+), DNS-Server: ([0-9a-fA-F\\.:]+) und \
            ([0-9a-fA-F\\.:]+), Gateway: ([0-9a-fA-F\\.:]+)").unwrap();
    }
    if NO_ANSWER.is_match(msg) {
        return EntryKind::DslNoAnswer;
    }
    if let Some(matches) = READY.captures(msg) {
        let down: u64 = matches
            .get(1)
            .expect("Internal regex error (dl)")
            .as_str()
            .parse()
            .expect("Not a number");
        let up: u64 = matches
            .get(2)
            .expect("Internal regex error (up)")
            .as_str()
            .parse()
            .expect("Not a number");
        return EntryKind::DslReady(DslBandwidth {
            download: down,
            upload: up,
        });
    }
    if let Some(matches) = INTERNET_OK.captures(msg) {
        return EntryKind::InternetEstablished(InternetDetails {
            ip: matches
                .get(1)
                .expect("Internal regex error (ip)")
                .as_str()
                .into(),
            dns: vec![
                matches
                    .get(2)
                    .expect("Internal regex error (dns-1)")
                    .as_str()
                    .into(),
                matches
                    .get(3)
                    .expect("Internal regex error (dns-2)")
                    .as_str()
                    .into(),
            ],
            gateway: matches
                .get(4)
                .expect("Internal regex error (gateway)")
                .as_str()
                .into(),
        });
    }
    EntryKind::Unknown
}

/// Parses an input stream.
pub fn parse<B: BufRead>(mut buf: B) -> io::Result<Vec<Entry>> {
    lazy_static! {
        static ref LINE: Regex =
            Regex::new("(\\d{2}\\.\\d{2}\\.\\d{2}) (\\d{2}:\\d{2}:\\d{2}) (.*)").unwrap();
    }
    let mut r = Vec::new();
    while let Some(line) = get_string(&mut buf)? {
        if line.is_empty() {
            continue;
        }
        let captures = match LINE.captures(&line) {
            None => panic!["Unformatted line: {}", line],
            Some(x) => x,
        };
        let date_time_str = format!(
            "{} {}",
            captures
                .get(1)
                .expect("Internal regex error (date)")
                .as_str(),
            captures
                .get(2)
                .expect("Internal regex error (time)")
                .as_str()
        );
        let date_time: DateTime<Local> = Local
            .datetime_from_str(&date_time_str, "%d.%m.%y %H:%M:%S")
            .unwrap();
        let message = captures
            .get(3)
            .expect("Internal regex error (message)")
            .as_str();
        let entry_kind = parse_message(message);
        r.push(Entry {
            timestamp: date_time.timestamp(),
            message: message.to_string(),
            details: entry_kind,
        });
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    #[test]
    fn message_parsing() {
        assert_eq!(
            ::parse_message("DSL antwortet nicht (Keine DSL-Synchronisierung)."),
            ::EntryKind::DslNoAnswer
        );
        assert_eq!(
            ::parse_message(
                "DSL ist verfügbar (DSL-Synchronisierung besteht mit 23519/9936 kbit/s).",
            ),
            ::EntryKind::DslReady(::DslBandwidth {
                download: 23519u64,
                upload: 9936u64,
            })
        );
        assert_eq!(
            ::parse_message(
                "Internetverbindung wurde erfolgreich hergestellt. IP-Adresse: 89.13.155.243, \
                DNS-Server: 62.109.121.2 und 62.109.121.1, Gateway: 62.52.200.220, Breitband-PoP: \
                BOBJ02",
            ),
            ::EntryKind::InternetEstablished(::InternetDetails {
                ip: "89.13.155.243".into(),
                dns: vec!["62.109.121.2".into(), "62.109.121.1".into()],
                gateway: "62.52.200.220".into(),
            })
        );
    }

    #[test]
    fn empty_input() {
        let input = &b""[..];
        let res = ::parse(input);
        assert!(res.is_ok());
        let res = res.unwrap();
        assert!(res.is_empty());
    }

    #[test]
    fn one_message() {
        let input = r#"16.11.17 19:08:11 DSL antwortet nicht (Keine DSL-Synchronisierung)."#;
        let res = ::parse(input.as_bytes());
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(res.len(), 1);
        let entry: &::Entry = &res[0];
        assert_eq!(entry.details, ::EntryKind::DslNoAnswer);
        assert_eq!(
            entry.message,
            "DSL antwortet nicht (Keine DSL-Synchronisierung).".to_string()
        );
        assert_eq!(entry.timestamp, 1510855691i64);
    }

    #[test]
    fn normal_flow() {
        let input = "\
17.11.17 16:41:44 Internetverbindung wurde erfolgreich hergestellt. IP-Adresse: 89.13.155.243, DNS-Server: \
    62.109.121.2 und 62.109.121.1, Gateway: 62.52.200.220, Breitband-PoP: BOBJ02
17.11.17 16:41:16 PPPoE-Fehler: Zeitüberschreitung.
17.11.17 16:40:31 DSL ist verfügbar (DSL-Synchronisierung besteht mit 23519/9936 kbit/s).
17.11.17 16:38:49 DSL-Synchronisierung beginnt (Training).
17.11.17 16:38:40 Internetverbindung wurde getrennt.
17.11.17 16:38:40 PPPoE-Fehler: Zeitüberschreitung.
17.11.17 16:38:26 DSL antwortet nicht (Keine DSL-Synchronisierung).";
        let res = ::parse(input.as_bytes());
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(
            res,
            vec![
                ::Entry {
                    timestamp: 1510933304,
                    message: "Internetverbindung wurde erfolgreich hergestellt. IP-Adresse: \
                              89.13.155.243, DNS-Server: 62.109.121.2 und 62.109.121.1, Gateway: \
                              62.52.200.220, Breitband-PoP: BOBJ02"
                        .into(),
                    details: ::EntryKind::InternetEstablished(::InternetDetails {
                        ip: "89.13.155.243".into(),
                        dns: vec!["62.109.121.2".into(), "62.109.121.1".into()],
                        gateway: "62.52.200.220".into(),
                    }),
                },
                ::Entry {
                    timestamp: 1510933276,
                    message: "PPPoE-Fehler: Zeitüberschreitung.".into(),
                    details: ::EntryKind::Unknown,
                },
                ::Entry {
                    timestamp: 1510933231,
                    message: "DSL ist verfügbar (DSL-Synchronisierung besteht mit 23519/9936 \
                              kbit/s)."
                        .into(),
                    details: ::EntryKind::DslReady(::DslBandwidth {
                        download: 23519,
                        upload: 9936,
                    }),
                },
                ::Entry {
                    timestamp: 1510933129,
                    message: "DSL-Synchronisierung beginnt (Training).".into(),
                    details: ::EntryKind::Unknown,
                },
                ::Entry {
                    timestamp: 1510933120,
                    message: "Internetverbindung wurde getrennt.".into(),
                    details: ::EntryKind::Unknown,
                },
                ::Entry {
                    timestamp: 1510933120,
                    message: "PPPoE-Fehler: Zeitüberschreitung.".into(),
                    details: ::EntryKind::Unknown,
                },
                ::Entry {
                    timestamp: 1510933106,
                    message: "DSL antwortet nicht (Keine DSL-Synchronisierung).".into(),
                    details: ::EntryKind::DslNoAnswer,
                },
            ]
        );
    }
}
