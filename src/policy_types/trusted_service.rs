//! Shared `TrustedService` / `AttrMapping` records and the attribute-mapping parser.
//!
//! These shadow the cap'n proto `TrustedService` and `AttrMapping` structs. Each owns both
//! directions (`TryFrom<Reader>` to decode, `WriteTo<Builder>` to encode) so the compiler
//! (encode), `zpdump`, and the Visa Service (decode) all share one representation.

use crate::policy::v1;
use crate::policy_types::attribute::Attribute;
use crate::policy_types::error::AttrMappingError;
use crate::write_to::WriteTo;

/// Shadows the cap'n proto `AttrMapping` struct. One entry of a trusted service's
/// `returns_attributes` mapping.
#[derive(Debug, Clone, PartialEq)]
pub struct AttrMapping {
    /// LHS: what the service calls the attribute.
    pub service_attr_key: String,
    /// Trimmed RHS spelling, e.g. `"user.color"`, `"#device.tag"`, `"user.groups{}"`.
    /// Preserved verbatim (including `#`/`{}`) and round-tripped through capnp.
    pub zpr_attr_spec: String,
    /// Decoded form of `zpr_attr_spec` (single / multi / tag).
    pub attr: Attribute,
}

/// Shadows the cap'n proto `TrustedService` struct.
#[derive(Debug, Clone, PartialEq)]
pub struct TrustedService {
    pub service_id: String,
    pub expiration_seconds: u32,
    pub returns_attrs: Vec<AttrMapping>,
    pub identity_attrs: Vec<String>,
}

/// Decode a trimmed RHS attribute spec into an `Attribute`.
///
/// The spec is one of:
///   - `<class>.<name>`   — regular single-valued attribute
///   - `#<class>.<name>`  — tag attribute
///   - `<class>.<name>{}` — multi-valued attribute
///
/// We never use the "optional" flag in ZPLC.
fn parse_attr_spec(spec: &str, mapping: &str) -> Result<Attribute, AttrMappingError> {
    let attr = if let Some(stripped) = spec.strip_prefix('#') {
        Attribute::tag(stripped).build()
    } else if let Some(stripped) = spec.strip_suffix("{}") {
        Attribute::tuple(stripped).multi().build()
    } else {
        Attribute::tuple(spec).single().build()
    }
    .map_err(|source| AttrMappingError::Attribute {
        mapping: mapping.to_string(),
        source,
    })?;

    Ok(attr)
}

/// Parse a `"<service-key-name> -> <attribute-spec>"` mapping string.
///
/// Requires exactly one `->` delimiter; trims both sides and rejects an empty service key or
/// spec. Attribute names are not otherwise restricted — any valid ZPL name (including quoted
/// names) is accepted; the RHS spec's validity is enforced by the `Attribute` builder.
pub fn parse_attribute_mapping(mapping: &str) -> Result<AttrMapping, AttrMappingError> {
    let (lhs, rhs) = mapping
        .split_once("->")
        .ok_or_else(|| AttrMappingError::InvalidFormat(mapping.to_string()))?;
    if rhs.contains("->") {
        // more than one delimiter
        return Err(AttrMappingError::InvalidFormat(mapping.to_string()));
    }

    let service_attr_key = lhs.trim().to_string();
    let zpr_attr_spec = rhs.trim().to_string();

    if service_attr_key.is_empty() {
        return Err(AttrMappingError::EmptySide {
            mapping: mapping.to_string(),
            side: "service key",
        });
    }
    if zpr_attr_spec.is_empty() {
        return Err(AttrMappingError::EmptySide {
            mapping: mapping.to_string(),
            side: "attribute spec",
        });
    }

    let attr = parse_attr_spec(&zpr_attr_spec, mapping)?;

    Ok(AttrMapping {
        service_attr_key,
        zpr_attr_spec,
        attr,
    })
}

/// A capnp/utf8 read failure surfaces as an invalid record with `what` as context.
fn read_fail(what: &'static str) -> AttrMappingError {
    AttrMappingError::InvalidFormat(format!("<unreadable {what}>"))
}

impl TryFrom<v1::attr_mapping::Reader<'_>> for AttrMapping {
    type Error = AttrMappingError;

    fn try_from(reader: v1::attr_mapping::Reader<'_>) -> Result<Self, Self::Error> {
        let service_attr_key = reader
            .get_service_attr_key()
            .map_err(|_| read_fail("attr mapping"))?
            .to_string()
            .map_err(|_| read_fail("attr mapping"))?;
        let zpr_attr_spec = reader
            .get_zpr_attr_spec()
            .map_err(|_| read_fail("attr mapping"))?
            .to_string()
            .map_err(|_| read_fail("attr mapping"))?;

        // Re-derive `attr` from the stored RHS so the decoded form is available without
        // re-reading the spec elsewhere.
        let attr = parse_attr_spec(&zpr_attr_spec, &zpr_attr_spec)?;

        Ok(AttrMapping {
            service_attr_key,
            zpr_attr_spec,
            attr,
        })
    }
}

impl WriteTo<v1::attr_mapping::Builder<'_>> for AttrMapping {
    fn write_to(&self, bldr: &mut v1::attr_mapping::Builder) {
        bldr.set_service_attr_key(&self.service_attr_key);
        bldr.set_zpr_attr_spec(&self.zpr_attr_spec);
    }
}

impl TryFrom<v1::trusted_service::Reader<'_>> for TrustedService {
    type Error = AttrMappingError;

    fn try_from(reader: v1::trusted_service::Reader<'_>) -> Result<Self, Self::Error> {
        let service_id = reader
            .get_service_id()
            .map_err(|_| read_fail("trusted service"))?
            .to_string()
            .map_err(|_| read_fail("trusted service"))?;
        let expiration_seconds = reader.get_expiration_seconds();

        let mut returns_attrs = Vec::new();
        for m in reader
            .get_returns_attrs()
            .map_err(|_| read_fail("returns_attrs"))?
            .iter()
        {
            returns_attrs.push(AttrMapping::try_from(m)?);
        }

        let mut identity_attrs = Vec::new();
        for a in reader
            .get_identity_attrs()
            .map_err(|_| read_fail("identity_attrs"))?
            .iter()
        {
            identity_attrs.push(
                a.map_err(|_| read_fail("identity attr"))?
                    .to_string()
                    .map_err(|_| read_fail("identity attr"))?,
            );
        }

        Ok(TrustedService {
            service_id,
            expiration_seconds,
            returns_attrs,
            identity_attrs,
        })
    }
}

impl WriteTo<v1::trusted_service::Builder<'_>> for TrustedService {
    fn write_to(&self, bldr: &mut v1::trusted_service::Builder) {
        bldr.set_service_id(&self.service_id);
        bldr.set_expiration_seconds(self.expiration_seconds);

        let mut ra = bldr
            .reborrow()
            .init_returns_attrs(self.returns_attrs.len() as u32);
        for (i, m) in self.returns_attrs.iter().enumerate() {
            m.write_to(&mut ra.reborrow().get(i as u32));
        }

        let mut ids = bldr
            .reborrow()
            .init_identity_attrs(self.identity_attrs.len() as u32);
        for (i, id) in self.identity_attrs.iter().enumerate() {
            ids.set(i as u32, id);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::policy_types::attribute::AttrDomain;

    // --- parse_attribute_mapping: success forms ---

    #[test]
    fn test_parse_attribute_mapping_tag() {
        let m = parse_attribute_mapping("service_key -> #device.tag").unwrap();
        assert_eq!(m.service_attr_key, "service_key");
        assert_eq!(m.zpr_attr_spec, "#device.tag");
        assert_eq!(*m.attr.get_domain_ref(), AttrDomain::Device);
        assert_eq!(m.attr.zpl_value(), "device.tag");
        assert!(m.attr.is_tag());
        assert!(!m.attr.is_multi_valued());
        assert!(!m.attr.optional);
    }

    #[test]
    fn test_parse_attribute_mapping_multi_valued() {
        let m = parse_attribute_mapping("service_key -> user.groups{}").unwrap();
        assert_eq!(m.service_attr_key, "service_key");
        assert_eq!(m.zpr_attr_spec, "user.groups{}");
        assert_eq!(*m.attr.get_domain_ref(), AttrDomain::User);
        assert_eq!(m.attr.zpl_key(), "user.groups");
        assert!(m.attr.is_multi_valued());
        assert!(!m.attr.is_tag());
    }

    #[test]
    fn test_parse_attribute_mapping_single_valued() {
        let m = parse_attribute_mapping("service_key -> service.role").unwrap();
        assert_eq!(m.service_attr_key, "service_key");
        assert_eq!(m.zpr_attr_spec, "service.role");
        assert_eq!(*m.attr.get_domain_ref(), AttrDomain::Service);
        assert_eq!(m.attr.zpl_key(), "service.role");
        assert!(!m.attr.is_multi_valued());
        assert!(!m.attr.is_tag());
    }

    #[test]
    fn test_parse_attribute_mapping_whitespace_handling() {
        // surrounding whitespace on both sides is trimmed and not preserved
        let m = parse_attribute_mapping("  service_key  ->  user.name  ").unwrap();
        assert_eq!(m.service_attr_key, "service_key");
        assert_eq!(m.zpr_attr_spec, "user.name");
        assert_eq!(m.attr.zpl_key(), "user.name");
    }

    // --- parse_attribute_mapping: error forms ---

    #[test]
    fn test_parse_attribute_mapping_no_arrow() {
        let e = parse_attribute_mapping("invalid_format").unwrap_err();
        assert!(matches!(e, AttrMappingError::InvalidFormat(_)));
    }

    #[test]
    fn test_parse_attribute_mapping_too_many_arrows() {
        let e = parse_attribute_mapping("key -> attr -> extra").unwrap_err();
        assert!(matches!(e, AttrMappingError::InvalidFormat(_)));
    }

    #[test]
    fn test_parse_attribute_mapping_empty_service_key() {
        let e = parse_attribute_mapping("  -> user.name").unwrap_err();
        assert!(matches!(
            e,
            AttrMappingError::EmptySide {
                side: "service key",
                ..
            }
        ));
    }

    #[test]
    fn test_parse_attribute_mapping_empty_spec() {
        let e = parse_attribute_mapping("service_key ->   ").unwrap_err();
        assert!(matches!(
            e,
            AttrMappingError::EmptySide {
                side: "attribute spec",
                ..
            }
        ));
    }

    #[test]
    fn test_parse_attribute_mapping_service_key_is_unrestricted() {
        // The service's own name for the attribute is arbitrary external text; spaces and
        // other characters are accepted verbatim (no whitelist).
        let m = parse_attribute_mapping("has spaces & punctuation! -> user.name").unwrap();
        assert_eq!(m.service_attr_key, "has spaces & punctuation!");
        assert_eq!(m.zpr_attr_spec, "user.name");
    }

    // --- AttrMapping roundtrip (WriteTo + TryFrom) ---

    #[test]
    fn test_attr_mapping_roundtrip() {
        let original = parse_attribute_mapping("groups -> user.groups{}").unwrap();
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::attr_mapping::Builder<'_> = msg.init_root();
            original.write_to(&mut root);
        }
        let reader: v1::attr_mapping::Reader<'_> = msg.get_root_as_reader().unwrap();
        let result = AttrMapping::try_from(reader).unwrap();
        assert_eq!(result, original);
    }

    // --- TrustedService roundtrip (WriteTo + TryFrom) ---

    #[test]
    fn test_trusted_service_roundtrip() {
        let original = TrustedService {
            service_id: "attrfile".to_string(),
            expiration_seconds: 3600,
            returns_attrs: vec![
                parse_attribute_mapping("color -> user.color").unwrap(),
                parse_attribute_mapping("hair -> #device.tag").unwrap(),
                parse_attribute_mapping("groups -> user.groups{}").unwrap(),
            ],
            identity_attrs: vec!["color".to_string()],
        };
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::trusted_service::Builder<'_> = msg.init_root();
            original.write_to(&mut root);
        }
        let reader: v1::trusted_service::Reader<'_> = msg.get_root_as_reader().unwrap();
        let result = TrustedService::try_from(reader).unwrap();
        assert_eq!(result, original);
        // mappings preserved in declaration order with exact trimmed RHS spelling
        assert_eq!(result.returns_attrs[0].zpr_attr_spec, "user.color");
        assert_eq!(result.returns_attrs[1].zpr_attr_spec, "#device.tag");
        assert_eq!(result.returns_attrs[2].zpr_attr_spec, "user.groups{}");
    }

    #[test]
    fn test_trusted_service_roundtrip_empty() {
        let original = TrustedService {
            service_id: "bas".to_string(),
            expiration_seconds: 0,
            returns_attrs: vec![],
            identity_attrs: vec![],
        };
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::trusted_service::Builder<'_> = msg.init_root();
            original.write_to(&mut root);
        }
        let reader: v1::trusted_service::Reader<'_> = msg.get_root_as_reader().unwrap();
        let result = TrustedService::try_from(reader).unwrap();
        assert_eq!(result, original);
    }

    // --- old policy with no field 7 decodes as an empty trusted-service list ---

    #[test]
    fn test_policy_without_trusted_services_is_empty() {
        // A policy that never sets field 7 decodes as an absent / empty trusted-service list.
        let mut msg = capnp::message::Builder::new_default();
        msg.init_root::<v1::policy::Builder<'_>>();
        let reader: v1::policy::Reader<'_> = msg.get_root_as_reader().unwrap();
        assert!(!reader.has_trusted_services());
        assert_eq!(reader.get_trusted_services().unwrap().len(), 0);
    }
}
