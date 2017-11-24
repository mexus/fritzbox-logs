//! Fritz!Box logs parsing library
//!
//! Currently only textual logs could be parsed. To fetch the logs one can use a python module
//! [fritzconnection](https://pypi.python.org/pypi/fritzconnection) from a command line like the
//! following:
//!
//! ```sh
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
#[macro_use]
extern crate quick_error;
#[macro_use]
extern crate log;

pub mod error;

use std::io::BufRead;
use chrono::{Local, TimeZone};
use regex::Regex;
use error::Error;

/// Bandwitdh information.
#[derive(Ord, PartialOrd, Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
#[derive(Debug)]
pub struct DslReadyDetails {
    /// Download bandwidth, kbit/s.
    pub download: u64,
    /// Upload bandwidth, kbit/s.
    pub upload: u64,
}

impl DslReadyDetails {
    /// Tries to parse a message as if it is a message about the dsl connection was
    /// established. If it is something else `None` is returned.
    fn parse_message(msg: &str) -> Result<Option<DslReadyDetails>, Error> {
        lazy_static! {
            static ref READY: Regex = Regex::new("DSL ist verfügbar \\(DSL-Synchronisierung \
                besteht mit (\\d+)/(\\d+) kbit/s\\).").unwrap();
        }
        let matches = match READY.captures(msg) {
            None => return Ok(None),
            Some(x) => x,
        };
        let down: u64 = matches
            .get(1)
            .ok_or(Error::RegexInternal("ready message: dl".into()))?
            .as_str()
            .parse()?;
        let up: u64 = matches
            .get(2)
            .ok_or(Error::RegexInternal("ready message: up".into()))?
            .as_str()
            .parse()?;
        return Ok(Some(DslReadyDetails {
            download: down,
            upload: up,
        }));
    }
}

/// Details about the internet connection.
#[derive(Ord, PartialOrd, Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
#[derive(Debug)]
pub struct InternetEstablishedDetails {
    /// Ip address.
    pub ip: String,
    /// DNS (usually two of them).
    pub dns: Vec<String>,
    /// Gateway.
    pub gateway: String,
}

impl InternetEstablishedDetails {
    /// Tries to parse a message as if it is a message about the internet connection was
    /// established. If it is something else `None` is returned.
    fn parse_message(msg: &str) -> Result<Option<Self>, Error> {
        lazy_static! {
            static ref INTERNET_OK: Regex = Regex::new("Internetverbindung wurde erfolgreich \
                hergestellt\\. IP-Adresse: ([0-9a-fA-F\\.:]+), DNS-Server: ([0-9a-fA-F\\.:]+) und \
                ([0-9a-fA-F\\.:]+), Gateway: ([0-9a-fA-F\\.:]+)").unwrap();
        }
        let matches = match INTERNET_OK.captures(msg) {
            None => return Ok(None),
            Some(x) => x,
        };
        return Ok(Some(InternetEstablishedDetails {
            ip: matches
                .get(1)
                .ok_or(Error::RegexInternal("internet-ok message: ip".into()))?
                .as_str()
                .into(),
            dns: vec![
                matches
                    .get(2)
                    .ok_or(Error::RegexInternal("internet-ok message: dns-1".into()))?
                    .as_str()
                    .into(),
                matches
                    .get(3)
                    .ok_or(Error::RegexInternal("internet-ok message: dns-2".into()))?
                    .as_str()
                    .into(),
            ],
            gateway: matches
                .get(4)
                .ok_or(Error::RegexInternal("internet-ok message: gateway".into()))?
                .as_str()
                .into(),
        }));
    }
}

/// Kind of a log entry.
#[derive(Ord, PartialOrd, Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
#[derive(Debug)]
pub enum EntryKind {
    /// German: 'DSL antwortet nicht'.
    DslNoAnswer,
    /// German: 'DSL ist verfügbar'.
    DslReady(DslReadyDetails),
    /// German: 'Internetverbindung wurde erfolgreich hergestellt'.
    InternetEstablished(InternetEstablishedDetails),
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

/// Extracts an entry kind (and its details) from a message.
fn parse_message(msg: &str) -> Result<EntryKind, Error> {
    lazy_static! {
        static ref NO_ANSWER: Regex = Regex::new("DSL antwortet nicht \\(Keine \
            DSL-Synchronisierung\\)\\.").unwrap();
    }
    Ok(if NO_ANSWER.is_match(msg) {
        EntryKind::DslNoAnswer
    } else if let Some(details) = DslReadyDetails::parse_message(msg)? {
        EntryKind::DslReady(details)
    } else if let Some(details) = InternetEstablishedDetails::parse_message(msg)? {
        EntryKind::InternetEstablished(details)
    } else {
        info!["Unknown message: {}", msg];
        EntryKind::Unknown
    })
}

/// Parses an input stream.
/// It is assumed that entries are given in a local time zone. If a line doesn't follow a format of
/// `[date] [time] message` (where `date` is `dd.mm.yy` and `time` is `hh:mm:ss`) an error is
/// returned. Unknown messages are also added to the result (although an info log is printed).
pub fn parse<B: BufRead>(buf: B) -> Result<Vec<Entry>, Error> {
    lazy_static! {
        static ref LINE: Regex =
            Regex::new("(\\d{2}\\.\\d{2}\\.\\d{2}) (\\d{2}:\\d{2}:\\d{2}) (.*)").unwrap();
    }
    let mut r = Vec::new();
    for line in buf.lines() {
        let line = line?.trim().to_string();
        if line.is_empty() {
            continue;
        }
        let captures = LINE.captures(&line).ok_or(Error::RegexFormat(
            line.clone(),
            "log line parsing".into(),
        ))?;
        let date_time_str = format!(
            "{} {}",
            captures
                .get(1)
                .ok_or(Error::RegexInternal("log entry line: date".into()))?
                .as_str(),
            captures
                .get(2)
                .ok_or(Error::RegexInternal("log entry line: time".into()))?
                .as_str()
        );
        let date_time = Local.datetime_from_str(&date_time_str, "%d.%m.%y %H:%M:%S")?;
        let message = captures
            .get(3)
            .ok_or(Error::RegexInternal("log entry line: message".into()))?
            .as_str();
        let entry_kind = parse_message(message)?;
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
    fn local_timestamp_from_text(date: &str) -> i64 {
        use chrono::{Local, TimeZone};
        Local
            .datetime_from_str(date, "%d.%m.%y %H:%M:%S")
            .unwrap()
            .timestamp()
    }

    #[test]
    fn message_parsing() {
        assert_eq!(
            ::parse_message("DSL antwortet nicht (Keine DSL-Synchronisierung).").unwrap(),
            ::EntryKind::DslNoAnswer
        );
        assert_eq!(
            ::parse_message(
                "DSL ist verfügbar (DSL-Synchronisierung besteht mit 23519/9936 kbit/s).",
            ).unwrap(),
            ::EntryKind::DslReady(::DslReadyDetails {
                download: 23519u64,
                upload: 9936u64,
            })
        );
        assert_eq!(
            ::parse_message(
                "Internetverbindung wurde erfolgreich hergestellt. IP-Adresse: 89.13.155.243, \
                DNS-Server: 62.109.121.2 und 62.109.121.1, Gateway: 62.52.200.220, Breitband-PoP: \
                BOBJ02",
            ).unwrap(),
            ::EntryKind::InternetEstablished(::InternetEstablishedDetails {
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
        assert!(res.unwrap().is_empty());
    }

    #[test]
    fn one_message() {
        let input = r#"16.11.17 19:08:11 DSL antwortet nicht (Keine DSL-Synchronisierung)."#;
        let res = ::parse(input.as_bytes()).unwrap();
        assert_eq!(res.len(), 1);
        let entry = &res[0];
        assert_eq!(entry.details, ::EntryKind::DslNoAnswer);
        assert_eq!(
            entry.message,
            "DSL antwortet nicht (Keine DSL-Synchronisierung).".to_string()
        );
        assert_eq!(
            entry.timestamp,
            local_timestamp_from_text("16.11.17 19:08:11")
        );
    }

    #[test]
    fn normal_flow() {
        let input = "\
17.11.17 16:41:44 Internetverbindung wurde erfolgreich hergestellt. IP-Adresse: 89.13.155.243, \
    DNS-Server: 62.109.121.2 und 62.109.121.1, Gateway: 62.52.200.220, Breitband-PoP: BOBJ02
17.11.17 16:41:16 PPPoE-Fehler: Zeitüberschreitung.
17.11.17 16:40:31 DSL ist verfügbar (DSL-Synchronisierung besteht mit 23519/9936 kbit/s).
17.11.17 16:38:49 DSL-Synchronisierung beginnt (Training).
17.11.17 16:38:40 Internetverbindung wurde getrennt.
17.11.17 16:38:40 PPPoE-Fehler: Zeitüberschreitung.
17.11.17 16:38:26 DSL antwortet nicht (Keine DSL-Synchronisierung).";
        let res = ::parse(input.as_bytes()).unwrap();
        assert_eq!(
            res,
            vec![
                ::Entry {
                    timestamp: local_timestamp_from_text("17.11.17 16:41:44"),
                    message: "Internetverbindung wurde erfolgreich hergestellt. IP-Adresse: \
                              89.13.155.243, DNS-Server: 62.109.121.2 und 62.109.121.1, Gateway: \
                              62.52.200.220, Breitband-PoP: BOBJ02"
                        .into(),
                    details: ::EntryKind::InternetEstablished(::InternetEstablishedDetails {
                        ip: "89.13.155.243".into(),
                        dns: vec!["62.109.121.2".into(), "62.109.121.1".into()],
                        gateway: "62.52.200.220".into(),
                    }),
                },
                ::Entry {
                    timestamp: local_timestamp_from_text("17.11.17 16:41:16"),
                    message: "PPPoE-Fehler: Zeitüberschreitung.".into(),
                    details: ::EntryKind::Unknown,
                },
                ::Entry {
                    timestamp: local_timestamp_from_text("17.11.17 16:40:31"),
                    message: "DSL ist verfügbar (DSL-Synchronisierung besteht mit 23519/9936 \
                              kbit/s)."
                        .into(),
                    details: ::EntryKind::DslReady(::DslReadyDetails {
                        download: 23519,
                        upload: 9936,
                    }),
                },
                ::Entry {
                    timestamp: local_timestamp_from_text("17.11.17 16:38:49"),
                    message: "DSL-Synchronisierung beginnt (Training).".into(),
                    details: ::EntryKind::Unknown,
                },
                ::Entry {
                    timestamp: local_timestamp_from_text("17.11.17 16:38:40"),
                    message: "Internetverbindung wurde getrennt.".into(),
                    details: ::EntryKind::Unknown,
                },
                ::Entry {
                    timestamp: local_timestamp_from_text("17.11.17 16:38:40"),
                    message: "PPPoE-Fehler: Zeitüberschreitung.".into(),
                    details: ::EntryKind::Unknown,
                },
                ::Entry {
                    timestamp: local_timestamp_from_text("17.11.17 16:38:26"),
                    message: "DSL antwortet nicht (Keine DSL-Synchronisierung).".into(),
                    details: ::EntryKind::DslNoAnswer,
                },
            ]
        );
    }
}
