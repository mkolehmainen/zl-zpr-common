use thiserror::Error;

#[derive(Debug, Error)]
pub enum AttributeError {
    #[error("Invalid attribute domain: {0}")]
    InvalidDomain(String),

    #[error("Invalid attribute: {0}")]
    ParseError(String),

    #[error("Invalid operation: {0}")]
    InvalidOperation(String),

    #[error("Invalid prefix: {0}")]
    InvalidPrefix(String),
}

#[derive(Debug, Error)]
pub enum PolicyTypeError {
    #[error("attribute error: {0}")]
    AttributeError(#[from] AttributeError),

    #[error("Deserialization error: {0:?}")]
    DeserializationError(&'static str),

    #[error("Cap'n Proto error: {0}")]
    Capnp(#[from] capnp::Error),

    #[error("Cap'n Proto schema error: {0}")]
    NotInSchema(#[from] capnp::NotInSchema),

    #[error("Cap'n Proto utf8 error: {0}")]
    Utf8Error(#[from] core::str::Utf8Error),

    #[error("IP address parse error: {0}")]
    AddrParseError(#[from] std::net::AddrParseError),

    #[error("attribute mapping error: {0}")]
    AttrMapping(#[from] AttrMappingError),
}

#[derive(Debug, Error)]
pub enum AttrMappingError {
    #[error(
        "invalid attribute mapping '{0}', must be of the form '<service-key-name> -> <attribute-spec>'"
    )]
    InvalidFormat(String),

    #[error("attribute mapping '{mapping}' has an empty {side}")]
    EmptySide { mapping: String, side: &'static str },

    #[error("attribute error in mapping '{mapping}': {source}")]
    Attribute {
        mapping: String,
        source: AttributeError,
    },
}
