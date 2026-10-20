//! Errors of a TLS connection. Every error that ends the connection
//! carries the alert sent to the peer, so the alert and the error the
//! caller sees can never disagree.

pub mod alert {
    pub const CLOSE_NOTIFY: u8 = 0;
    pub const UNEXPECTED_MESSAGE: u8 = 10;
    pub const BAD_RECORD_MAC: u8 = 20;
    pub const RECORD_OVERFLOW: u8 = 22;
    pub const HANDSHAKE_FAILURE: u8 = 40;
    pub const BAD_CERTIFICATE: u8 = 42;
    pub const UNSUPPORTED_CERTIFICATE: u8 = 43;
    pub const CERTIFICATE_REVOKED: u8 = 44;
    pub const CERTIFICATE_EXPIRED: u8 = 45;
    pub const CERTIFICATE_UNKNOWN: u8 = 46;
    pub const ILLEGAL_PARAMETER: u8 = 47;
    pub const UNKNOWN_CA: u8 = 48;
    pub const ACCESS_DENIED: u8 = 49;
    pub const DECODE_ERROR: u8 = 50;
    pub const DECRYPT_ERROR: u8 = 51;
    pub const PROTOCOL_VERSION: u8 = 70;
    pub const INSUFFICIENT_SECURITY: u8 = 71;
    pub const INTERNAL_ERROR: u8 = 80;
    pub const INAPPROPRIATE_FALLBACK: u8 = 86;
    pub const USER_CANCELED: u8 = 90;
    pub const MISSING_EXTENSION: u8 = 109;
    pub const UNSUPPORTED_EXTENSION: u8 = 110;
    pub const UNRECOGNIZED_NAME: u8 = 112;
    pub const UNKNOWN_PSK_IDENTITY: u8 = 115;
    pub const CERTIFICATE_REQUIRED: u8 = 116;
    pub const NO_APPLICATION_PROTOCOL: u8 = 120;

    pub fn name(a: u8) -> &'static str {
        match a {
            CLOSE_NOTIFY => "close_notify",
            UNEXPECTED_MESSAGE => "unexpected_message",
            BAD_RECORD_MAC => "bad_record_mac",
            RECORD_OVERFLOW => "record_overflow",
            HANDSHAKE_FAILURE => "handshake_failure",
            BAD_CERTIFICATE => "bad_certificate",
            UNSUPPORTED_CERTIFICATE => "unsupported_certificate",
            CERTIFICATE_REVOKED => "certificate_revoked",
            CERTIFICATE_EXPIRED => "certificate_expired",
            CERTIFICATE_UNKNOWN => "certificate_unknown",
            ILLEGAL_PARAMETER => "illegal_parameter",
            UNKNOWN_CA => "unknown_ca",
            ACCESS_DENIED => "access_denied",
            DECODE_ERROR => "decode_error",
            DECRYPT_ERROR => "decrypt_error",
            PROTOCOL_VERSION => "protocol_version",
            INSUFFICIENT_SECURITY => "insufficient_security",
            INTERNAL_ERROR => "internal_error",
            INAPPROPRIATE_FALLBACK => "inappropriate_fallback",
            USER_CANCELED => "user_canceled",
            MISSING_EXTENSION => "missing_extension",
            UNSUPPORTED_EXTENSION => "unsupported_extension",
            UNRECOGNIZED_NAME => "unrecognized_name",
            UNKNOWN_PSK_IDENTITY => "unknown_psk_identity",
            CERTIFICATE_REQUIRED => "certificate_required",
            NO_APPLICATION_PROTOCOL => "no_application_protocol",
            _ => "unknown alert",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// This side found a problem, sent `alert` and closed.
    Local { alert: u8, reason: &'static str },
    /// The peer sent this fatal alert.
    Peer(u8),
    /// The connection was already closed or failed before this call.
    Closed,
}

impl Error {
    pub(crate) fn new(alert: u8, reason: &'static str) -> Error {
        Error::Local { alert, reason }
    }
    pub(crate) fn decode(reason: &'static str) -> Error {
        Error::new(alert::DECODE_ERROR, reason)
    }
    pub(crate) fn illegal(reason: &'static str) -> Error {
        Error::new(alert::ILLEGAL_PARAMETER, reason)
    }
    pub(crate) fn unexpected(reason: &'static str) -> Error {
        Error::new(alert::UNEXPECTED_MESSAGE, reason)
    }
    pub(crate) fn internal(reason: &'static str) -> Error {
        Error::new(alert::INTERNAL_ERROR, reason)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Local { alert: a, reason } => {
                write!(f, "{reason} (sent {})", alert::name(*a))
            }
            Error::Peer(a) => write!(f, "peer sent {}", alert::name(*a)),
            Error::Closed => f.write_str("connection closed"),
        }
    }
}

impl std::error::Error for Error {}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    }
}
