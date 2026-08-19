//! Shared implementations of types related to the policy Capn Proto.

mod attr_exp;
mod attribute;
mod error;
mod join;
mod policy_bundle;
mod topology;
mod trusted_service;
mod writer;

pub use attr_exp::{AttrExp, AttrOp};
pub use attribute::{AttrDomain, Attribute, ZPR_TAG_KEY_PREFIX, is_reserved_tag_name};
pub use error::{AttrMappingError, AttributeError, PolicyTypeError};
pub use join::{JoinPolicy, PFlags, Scope, ScopeFlag, Service, ServiceType};
pub use policy_bundle::{PolicyBundle, PolicyContainerBytes};
pub use topology::{NetAddr, NetworkHost, Peering};
pub use trusted_service::{AttrMapping, TrustedService, parse_attribute_mapping};
pub use writer::write_attributes;
