use crate::vsapi::v1;
use std::net::AddrParseError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VsapiTypeError {
    #[error("capn proto error: {0}")]
    Capnp(#[from] capnp::Error),

    #[error("capn proto not in schema: {0}")]
    CapnpNotInSchema(#[from] capnp::NotInSchema),

    #[error("string conversion error: {0}")]
    StringConversion(#[from] std::str::Utf8Error),

    #[error("Serialization error {0}")]
    SerializationError(&'static str),

    #[error("Deserialization error: {0:?}")]
    DeserializationError(&'static str),

    #[error("IP address conversion error: {0}")]
    TryFromSliceError(#[from] std::array::TryFromSliceError),

    #[error("Addr Parse Error")]
    AddrParseError(#[from] AddrParseError),
}

/// Error information.
/// Mirrors the "Error" struct in the vsapi.
#[derive(Debug, Error)]
pub struct ApiResponseError {
    pub code: ErrorCode,
    pub message: String,
    pub retry_in: u32,
}

impl std::fmt::Display for ApiResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            " {:?}: {} (retry in {} seconds)",
            self.code, self.message, self.retry_in
        )
    }
}

/// Denial code, match the codes in vs.capnp, except for Fail and UnknownStatusCode
#[derive(Clone, Debug)]
pub enum ErrorCode {
    Internal,
    AuthRequired,
    InvalidOperation,
    OutOfSync,
    NotFound,
    InvalidSignature,
    QuotaExceeded,
    TemporarilyUnavailable,
    AuthError,
    ParamError,
    /// Authentication succeeded; no join policy admits this endpoint.
    PolicyDenied,
    UnknownStatusCode,
    Fail,
}

impl ApiResponseError {
    pub fn new<S: Into<String>>(code: ErrorCode, message: S, retry_in: u32) -> Self {
        Self {
            code,
            message: message.into(),
            retry_in,
        }
    }

    /// Sets retry value to 0.
    pub fn new_code_msg<S: Into<String>>(code: ErrorCode, message: S) -> Self {
        Self {
            code,
            message: message.into(),
            retry_in: 0,
        }
    }
}

impl TryFrom<v1::error::Reader<'_>> for ApiResponseError {
    type Error = VsapiTypeError;

    // Altered to match functionality of former libnode2::vsconn::new_coded_error
    fn try_from(reader: v1::error::Reader<'_>) -> Result<Self, Self::Error> {
        let code: ErrorCode = reader.get_code()?.into();
        let message = reader.get_message()?.to_string()?;
        let retry_in = reader.get_retry_in();

        Ok(ApiResponseError {
            code,
            message,
            retry_in,
        })
    }
}

impl Into<v1::ErrorCode> for ErrorCode {
    fn into(self) -> v1::ErrorCode {
        match self {
            ErrorCode::Internal => v1::ErrorCode::Internal,
            ErrorCode::AuthRequired => v1::ErrorCode::AuthRequired,
            ErrorCode::InvalidOperation => v1::ErrorCode::InvalidOperation,
            ErrorCode::OutOfSync => v1::ErrorCode::OutOfSync,
            ErrorCode::NotFound => v1::ErrorCode::NotFound,
            ErrorCode::InvalidSignature => v1::ErrorCode::InvalidSignature,
            ErrorCode::QuotaExceeded => v1::ErrorCode::QuotaExceeded,
            ErrorCode::TemporarilyUnavailable => v1::ErrorCode::TemporarilyUnavailable,
            ErrorCode::AuthError => v1::ErrorCode::AuthError,
            ErrorCode::ParamError => v1::ErrorCode::ParamError,
            ErrorCode::PolicyDenied => v1::ErrorCode::PolicyDenied,

            // These are not 1:1 mapped to IDL.
            ErrorCode::UnknownStatusCode => v1::ErrorCode::Internal,
            ErrorCode::Fail => v1::ErrorCode::Internal,
        }
    }
}
