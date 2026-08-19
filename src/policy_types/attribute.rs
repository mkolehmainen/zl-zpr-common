use crate::policy_types::error::AttributeError;
use std::fmt;
use std::fmt::Write;

pub const ATTR_DOMAIN_SERVICE: &str = "service";
pub const ATTR_DOMAIN_USER: &str = "user";
pub const ATTR_DOMAIN_DEVICE: &str = "device";
pub const ATTR_DOMAIN_LINK: &str = "link";
pub const ATTR_DOMAIN_ZPR_INTERNAL: &str = "zpr";

/// Name-space (within a domain) reserved for the tag encoding: a tag named `red` in the
/// user domain is encoded with the attribute key `user.zpr.tag.red`.
pub const ZPR_TAG_KEY_PREFIX: &str = "zpr.tag";

/// True if `name` (an attribute name without its domain prefix) is reserved for the
/// tag encoding and therefore not usable as an ordinary attribute name.
pub fn is_reserved_tag_name(name: &str) -> bool {
    name == ZPR_TAG_KEY_PREFIX || name.starts_with("zpr.tag.")
}

fn validate_tuple_name(name: &str) -> Result<(), AttributeError> {
    if is_reserved_tag_name(name) {
        return Err(AttributeError::InvalidOperation(format!(
            "attribute name '{name}' is reserved for tag encoding"
        )));
    }
    Ok(())
}

/// A ZPL attribute. Could be a tuple type attribute, eg "user.role:marketing" or a
/// tag type.  An attribute may be optional or required, and may be multi-valued
/// or single-valued.
#[derive(Debug, Clone, PartialEq)]
pub struct Attribute {
    domain: AttrDomain,
    name: String, // For a tag this is the tag name, else this is the attribute name.
    values: Option<Vec<String>>, // For a tag, this is always None.
    attr_type: AttrT,
    pub optional: bool,
}

/// An attribute must live in one of our domains. When parsing sometimes we
/// end up in an intermediate state where we don't know the domain yet so
/// we use `Unspecified`.  An error will occur if we try to write policy
/// and there remain any unspecified domains.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy)]
pub enum AttrDomain {
    Unspecified,
    Device,
    User,
    Service,
    Link,
    ZprInternal, // For compiler/visa-service use only
}

impl fmt::Display for AttrDomain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AttrDomain::Device => write!(f, "{}", ATTR_DOMAIN_DEVICE),
            AttrDomain::User => write!(f, "{}", ATTR_DOMAIN_USER),
            AttrDomain::Service => write!(f, "{}", ATTR_DOMAIN_SERVICE),
            AttrDomain::Link => write!(f, "{}", ATTR_DOMAIN_LINK),
            AttrDomain::ZprInternal => write!(f, "{}", ATTR_DOMAIN_ZPR_INTERNAL),
            AttrDomain::Unspecified => write!(f, "UNSPECIFIED"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AttrT {
    Tag,
    SingleValued,
    MultiValued,
}

/// Strategy to use when parsing attribute names and a domain is
/// not present.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DomainFallback {
    UseHint(AttrDomain),
    UseUnspecified,
    ErrorIfMissing,
}

pub struct TagAttrBuilder {
    raw_name: String,
    optional: bool,
    domain_fb: DomainFallback,
}

pub struct TupleAttrBuilder {
    raw_name: String,
    attr_type: AttrT,
    values: Option<Vec<String>>,
    optional: bool,
    domain_fb: DomainFallback,
}

/// Used to build an attribute that holds a tag.
impl TagAttrBuilder {
    fn new<N: Into<String>>(name: N) -> Self {
        TagAttrBuilder {
            raw_name: name.into(),
            optional: false,
            domain_fb: DomainFallback::ErrorIfMissing,
        }
    }

    pub fn optional(mut self, optional: bool) -> Self {
        self.optional = optional;
        self
    }

    pub fn domain_hint(mut self, domain: AttrDomain) -> Self {
        self.domain_fb = DomainFallback::UseHint(domain);
        self
    }

    pub fn allow_unspecified(mut self) -> Self {
        self.domain_fb = DomainFallback::UseUnspecified;
        self
    }

    pub fn build(self) -> Result<Attribute, AttributeError> {
        let (domain, name) = resolve_domain(&self.raw_name, self.domain_fb)?;
        Ok(Attribute {
            domain,
            name,
            values: None,
            attr_type: AttrT::Tag,
            optional: self.optional,
        })
    }
}

/// Used to build an attribute that holds a tuple that may also be multi-valued.
impl TupleAttrBuilder {
    fn new<N: Into<String>>(name: N) -> Self {
        TupleAttrBuilder {
            raw_name: name.into(),
            attr_type: AttrT::SingleValued,
            values: None,
            optional: false,
            domain_fb: DomainFallback::ErrorIfMissing,
        }
    }

    pub fn single(mut self) -> Self {
        self.attr_type = AttrT::SingleValued;
        self
    }

    /// Note that single-valued is the default.
    pub fn multi(mut self) -> Self {
        self.attr_type = AttrT::MultiValued;
        self
    }

    pub fn multi_if(mut self, multi: bool) -> Self {
        if multi {
            self.attr_type = AttrT::MultiValued;
        } else {
            self.attr_type = AttrT::SingleValued;
        }
        self
    }

    pub fn optional(mut self, optional: bool) -> Self {
        self.optional = optional;
        self
    }

    pub fn value<V: Into<String>>(mut self, v: V) -> Self {
        self.values = Some(vec![v.into()]);
        self
    }

    /// If you sent more than one value the resulting tuple will be
    /// multi-valued type (you do not need to explicitly call `multi()`).
    pub fn values(mut self, vals: Vec<String>) -> Self {
        self.values = Some(vals);
        self
    }

    pub fn values_opt(mut self, opt_vals: Option<Vec<String>>) -> Self {
        if opt_vals.is_some() {
            self.values = opt_vals;
        }
        self
    }

    pub fn domain_hint(mut self, hint: AttrDomain) -> Self {
        self.domain_fb = DomainFallback::UseHint(hint);
        self
    }

    pub fn allow_unspecified(mut self) -> Self {
        self.domain_fb = DomainFallback::UseUnspecified;
        self
    }

    pub fn build(self) -> Result<Attribute, AttributeError> {
        let (domain, name) = resolve_domain(&self.raw_name, self.domain_fb)?;
        // Tags are encoded with `<domain>.zpr.tag.<name>` keys, so ordinary
        // attributes may not use names in that space.
        validate_tuple_name(&name)?;
        let attr_type = match (&self.values, self.attr_type) {
            (_, AttrT::MultiValued) => AttrT::MultiValued, // explicitly set by caller
            (Some(v), AttrT::SingleValued) if v.len() > 1 => AttrT::MultiValued, // inferred from values
            _ => AttrT::SingleValued,
        };
        Ok(Attribute {
            domain,
            name,
            values: self.values,
            attr_type,
            optional: self.optional,
        })
    }
}

fn resolve_domain(name: &str, fb: DomainFallback) -> Result<(AttrDomain, String), AttributeError> {
    match Attribute::parse_domain(name) {
        Ok(pair) => Ok(pair),
        Err(_) => match fb {
            DomainFallback::UseHint(hint) => Ok((hint, name.into())),
            DomainFallback::UseUnspecified => Ok((AttrDomain::Unspecified, name.into())),
            DomainFallback::ErrorIfMissing => Err(AttributeError::InvalidDomain(name.into())),
        },
    }
}

impl Attribute {
    /// New API using the builders.  The other new_xxx functions that create tags use this.
    pub fn tag<N: Into<String>>(name: N) -> TagAttrBuilder {
        TagAttrBuilder::new(name)
    }

    /// New API using the builders.  The other new_xxx functions that create singel or
    /// multi-value attributes use this.
    pub fn tuple<N: Into<String>>(name: N) -> TupleAttrBuilder {
        TupleAttrBuilder::new(name)
    }

    /// String form of the attribute that also includes the schema hints like
    /// the '{}' suffix for multi-valued and '?' for optional.
    pub fn to_schema_string(&self) -> String {
        let mut f = String::new();
        let key = format!("{}.{}", self.domain, self.name);

        if self.is_tag() {
            write!(f, "#{}", key).unwrap();
        } else if let Some(v) = &self.values {
            if v.is_empty() {
                write!(f, "{key}:").unwrap();
            } else if v.len() == 1 {
                write!(f, "{key}:{}", v[0]).unwrap();
            } else {
                write!(f, "{key}:{{{}}}", v.join(", ")).unwrap();
            }
        } else {
            write!(f, "{}", key).unwrap();
            if self.is_multi_valued() {
                write!(f, "{{}}").unwrap();
            }
            if self.optional {
                write!(f, "?").unwrap();
            }
        }
        f
    }

    /// String form of the attribute without the additional schema hints.
    pub fn to_instance_string(&self) -> String {
        let mut f = String::new();
        let key = format!("{}.{}", self.domain, self.name);
        if self.is_tag() {
            write!(f, "#{}", key).unwrap();
        } else if let Some(v) = &self.values {
            if v.is_empty() {
                write!(f, "{key}:").unwrap();
            } else if v.len() == 1 {
                write!(f, "{key}:{}", v[0]).unwrap();
            } else {
                write!(f, "{key}:{{{}}}", v.join(", ")).unwrap();
            }
        } else {
            // Not a tag and has no values not even empty?
            write!(f, "{}", key).unwrap();
        }
        f
    }

    /// Special constructor for ZPR internal attributes with a single value.
    pub fn try_zpr_internal_attr<S: Into<String>, T: Into<String>>(
        name: S,
        value: T,
    ) -> Result<Self, AttributeError> {
        match name
            .into()
            .strip_prefix(&format!("{}.", ATTR_DOMAIN_ZPR_INTERNAL))
        {
            Some(name_without_domain) => Attribute::tuple(name_without_domain)
                .domain_hint(AttrDomain::ZprInternal)
                .value(value)
                .build(),
            None => Err(AttributeError::InvalidPrefix(format!(
                "zpr internal attribute must start with {}.",
                ATTR_DOMAIN_ZPR_INTERNAL
            ))),
        }
    }

    /// Special constructor for ZPR internal attribute with single value but
    /// sets the MULTI_VALUE flag.
    pub fn try_zpr_internal_attr_mv<S: Into<String>, T: Into<String>>(
        name: S,
        value: T,
    ) -> Result<Self, AttributeError> {
        match name
            .into()
            .strip_prefix(&format!("{}.", ATTR_DOMAIN_ZPR_INTERNAL))
        {
            Some(name_without_domain) => Attribute::tuple(name_without_domain)
                .domain_hint(AttrDomain::ZprInternal)
                .multi()
                .value(value)
                .build(),
            None => Err(AttributeError::InvalidPrefix(format!(
                "zpr internal attribute must start with {}.",
                ATTR_DOMAIN_ZPR_INTERNAL
            ))),
        }
    }

    /// Create and return a new attribute with the same characteristics of this one but with the new name provided.
    /// If `new_name` includes a valid domain prefix, the returned attribute will have that domain.
    /// Ordinary attributes cannot be renamed into the namespace reserved for tag encoding.
    pub fn clone_with_new_name<S: Into<String>>(
        &self,
        new_name: S,
    ) -> Result<Self, AttributeError> {
        let mut new_a = self.clone();
        let new_name = new_name.into();
        let (dom, name) = match Attribute::parse_domain(&new_name) {
            Ok((d, n)) => (d, n),
            // If the new name does not have a domain prefix, use the current domain.
            Err(_) => (self.domain.clone(), new_name.to_string()),
        };
        if !self.is_tag() {
            validate_tuple_name(&name)?;
        }
        new_a.name = name;
        new_a.domain = dom;
        Ok(new_a)
    }

    pub fn is_tag(&self) -> bool {
        self.attr_type == AttrT::Tag
    }

    /// The attribute (or tag) name, without the domain prefix.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn is_single_valued(&self) -> bool {
        self.attr_type == AttrT::SingleValued
    }

    pub fn is_multi_valued(&self) -> bool {
        self.attr_type == AttrT::MultiValued
    }

    pub fn get_values(&self) -> Option<&[String]> {
        self.values.as_deref()
    }

    pub fn set_multi_valued(&mut self) -> Result<(), AttributeError> {
        if self.is_tag() {
            return Err(AttributeError::InvalidOperation(format!(
                "attempt to set tag as multi valued on {}",
                self.zplc_key()
            )));
        }
        self.attr_type = AttrT::MultiValued;
        Ok(())
    }

    /// Parse off one the ZPR domains from the key.  Does not work with ZPR internal domain.
    /// Returns `(<domain>, <rest>)` from given key.
    pub fn parse_domain(key: &str) -> Result<(AttrDomain, String), AttributeError> {
        if let Some(renamed) = key.strip_prefix(&format!("{}.", ATTR_DOMAIN_DEVICE)) {
            Ok((AttrDomain::Device, renamed.to_string()))
        } else if let Some(renamed) = key.strip_prefix(&format!("{}.", ATTR_DOMAIN_USER)) {
            Ok((AttrDomain::User, renamed.to_string()))
        } else if let Some(renamed) = key.strip_prefix(&format!("{}.", ATTR_DOMAIN_SERVICE)) {
            Ok((AttrDomain::Service, renamed.to_string()))
        } else if let Some(renamed) = key.strip_prefix(&format!("{}.", ATTR_DOMAIN_LINK)) {
            Ok((AttrDomain::Link, renamed.to_string()))
        } else {
            Err(AttributeError::InvalidDomain(key.to_string()))
        }
    }

    pub fn get_domain_ref(&self) -> &AttrDomain {
        &self.domain
    }

    pub fn is_unspecified_domain(&self) -> bool {
        self.domain == AttrDomain::Unspecified
    }

    pub fn is_domain(&self, domain: AttrDomain) -> bool {
        self.domain == domain
    }

    /// Update the domain.
    pub fn set_domain(&mut self, domain: AttrDomain) {
        self.domain = domain;
    }

    /// The the ZPL name for the key of this attribute. The key is just the attribute name
    /// unless this is a tag, in which case the key is "\<domain\>.zpr.tag.\<name\>".
    /// Each tag gets its own key so that tags never collide with each other and each
    /// carries its own source/expiration downstream.
    pub fn zpl_key(&self) -> String {
        if self.is_tag() {
            format!("{}.{}.{}", self.domain, ZPR_TAG_KEY_PREFIX, self.name)
        } else {
            format!("{}.{}", self.domain, self.name)
        }
    }

    /// The ZPL value for this attribute. If there is no value an empty string is returned.
    /// If there are multiple values a comma separated list is returned.
    /// Tags have no value (presence of the key is the tag).
    pub fn zpl_value(&self) -> String {
        if let (false, Some(v)) = (self.is_tag(), &self.values) {
            v.join(", ")
        } else {
            "".to_string()
        }
    }

    /// The set of values (which may be empty). Tags always have no values: a tag is
    /// encoded as a valueless `has` on its `zpl_key()`.
    pub fn zpl_values(&self) -> Vec<String> {
        if self.is_tag() {
            return vec![];
        }
        if let Some(v) = &self.values {
            let mut sorted_values = v.clone();
            sorted_values.sort();
            sorted_values
        } else {
            vec![]
        }
    }

    /// Write an attribute key name as it might appear in zplc.
    /// Value of the attribute is ignored.
    /// - tags look like `#domain.name`
    /// - regular tuples look like `domain.name`
    /// - multi-valued attributes look like `domain.name{}`
    pub fn zplc_key(&self) -> String {
        let mut result = String::new();
        if self.is_tag() {
            result.push_str("#");
        }
        result.push_str(&format!("{}.{}", self.domain, self.name));
        if self.is_multi_valued() {
            result.push_str("{}");
        }
        result
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_attributes_kv() {
        let a = Attribute::tuple("user.role")
            .single()
            .value("admin")
            .build()
            .unwrap();
        assert_eq!(a.domain, AttrDomain::User);
        assert_eq!(a.name, "role");
        assert_eq!(a.values, Some(vec!["admin".to_string()]));
        assert_eq!(a.is_multi_valued(), false);
        assert_eq!(a.is_tag(), false);
        assert_eq!(a.optional, false);
        assert_eq!("user.role:admin", a.to_instance_string());
        assert_eq!("user.role", a.zpl_key());
        assert_eq!("admin", a.zpl_value());
    }

    #[test]
    fn test_attributes_tag() {
        let a = Attribute::tag("device.hardened").build().unwrap();
        assert_eq!(a.domain, AttrDomain::Device);
        assert_eq!(a.name, "hardened");
        assert_eq!(a.values, None);
        assert_eq!(a.is_multi_valued(), false);
        assert_eq!(a.is_tag(), true);
        assert_eq!(a.optional, false);
        assert_eq!("#device.hardened", a.to_instance_string());
        assert_eq!("device.zpr.tag.hardened", a.zpl_key());
        assert_eq!("", a.zpl_value());
        assert!(a.zpl_values().is_empty());
    }

    #[test]
    fn test_attrributes_internal() {
        let a =
            Attribute::try_zpr_internal_attr("zpr.role", "admin").expect("zpr prefix not found");
        assert_eq!(a.domain, AttrDomain::ZprInternal);
        assert_eq!(a.name, "role");
        assert_eq!(a.values, Some(vec!["admin".to_string()]));
        assert_eq!(a.is_multi_valued(), false);
        assert_eq!(a.is_tag(), false);
        assert_eq!(a.optional, false);
        assert_eq!("zpr.role:admin", a.to_instance_string());
        assert_eq!("zpr.role", a.zpl_key());
        assert_eq!("admin", a.zpl_value());
    }

    #[test]
    fn test_zplc_key_regular_attribute() {
        let a = Attribute::tuple("user.role")
            .single()
            .value("admin")
            .build()
            .unwrap();
        assert_eq!("user.role", a.zplc_key());
    }

    #[test]
    fn test_zplc_key_tag_attribute() {
        let a = Attribute::tag("device.hardened").build().unwrap();
        assert_eq!("#device.hardened", a.zplc_key());
    }

    #[test]
    fn test_tag_representation() {
        let a = Attribute::tag("user.red").build().unwrap();
        assert_eq!("#user.red", a.to_instance_string());
        assert_eq!("#user.red", a.to_schema_string());
        assert_eq!("user.zpr.tag.red", a.zpl_key());
        assert_eq!("", a.zpl_value());
        assert!(a.zpl_values().is_empty());
    }

    #[test]
    fn test_reserved_tag_names() {
        assert!(is_reserved_tag_name("zpr.tag"));
        assert!(is_reserved_tag_name("zpr.tag.red"));
        assert!(!is_reserved_tag_name("zpr.tagged"));
        assert!(!is_reserved_tag_name("zpr.adapter.cn"));
        assert!(!is_reserved_tag_name("role"));
    }

    #[test]
    fn test_clone_with_new_name_rejects_reserved_tag_names_for_tuples() {
        let tuple = Attribute::tuple("user.role").build().unwrap();

        for name in ["user.zpr.tag", "user.zpr.tag.red", "zpr.tag.red"] {
            let error = tuple.clone_with_new_name(name).unwrap_err();
            assert!(
                matches!(error, AttributeError::InvalidOperation(_)),
                "{name}"
            );
        }

        let renamed = tuple.clone_with_new_name("device.posture").unwrap();
        assert_eq!(renamed.zpl_key(), "device.posture");
    }

    #[test]
    fn test_clone_with_new_name_allows_tag_names() {
        let tag = Attribute::tag("user.red").build().unwrap();
        let renamed = tag.clone_with_new_name("device.zpr.tag.red").unwrap();

        assert_eq!(renamed.zpl_key(), "device.zpr.tag.zpr.tag.red");
    }

    #[test]
    fn test_zplc_key_multi_valued_attribute() {
        let a = Attribute::tuple("user.groups").multi().build().unwrap();
        assert_eq!("user.groups{}", a.zplc_key());
    }

    // ZPLC does not use "?" notation.
    #[test]
    fn test_zplc_key_optional() {
        let mut a = Attribute::tuple("service.role").single().build().unwrap();
        a.optional = true;
        assert_eq!("service.role", a.zplc_key());
        let mut a = Attribute::tag("device.secure").build().unwrap();
        a.optional = true;
        assert_eq!("#device.secure", a.zplc_key());
        let mut a = Attribute::tuple("user.permissions")
            .multi()
            .build()
            .unwrap();
        a.optional = true;
        assert_eq!("user.permissions{}", a.zplc_key());
    }

    #[test]
    fn test_zplc_key_zpr_internal_attribute() {
        let a = Attribute::try_zpr_internal_attr("zpr.adapter.cn", "test")
            .expect("zpr prefix not found");
        assert_eq!("zpr.adapter.cn", a.zplc_key());
    }

    #[test]
    fn test_zplc_key_zpr_internal_multi_valued() {
        let a = Attribute::try_zpr_internal_attr_mv("zpr.roles", "admin")
            .expect("zpr prefix not found");
        assert_eq!("zpr.roles{}", a.zplc_key());
    }

    #[test]
    fn test_zplc_key_all_domains() {
        // Test each domain type
        let user_attr = Attribute::tuple("user.name")
            .single()
            .value("alice")
            .build()
            .unwrap();
        assert_eq!("user.name", user_attr.zplc_key());

        let service_attr = Attribute::tuple("service.type")
            .single()
            .value("web")
            .build()
            .unwrap();
        assert_eq!("service.type", service_attr.zplc_key());

        let device_attr = Attribute::tuple("device.ip")
            .single()
            .value("192.168.1.1")
            .build()
            .unwrap();
        assert_eq!("device.ip", device_attr.zplc_key());

        let zpr_attr =
            Attribute::try_zpr_internal_attr("zpr.test", "value").expect("zpr prefix not found");
        assert_eq!("zpr.test", zpr_attr.zplc_key());
    }

    #[test]
    fn test_parse_domain_link() {
        let (domain, name) = Attribute::parse_domain("link.bandwidth").unwrap();
        assert_eq!(domain, AttrDomain::Link);
        assert_eq!(name, "bandwidth");

        // Verify round-trip via builder
        let a = Attribute::tuple("link.bandwidth")
            .single()
            .value("1Gbps")
            .build()
            .unwrap();
        assert_eq!(a.domain, AttrDomain::Link);
        assert_eq!(a.name, "bandwidth");
        assert_eq!(a.values, Some(vec!["1Gbps".to_string()]));
        assert_eq!("link.bandwidth:1Gbps", a.to_instance_string());
        assert_eq!("link.bandwidth", a.zpl_key());
        assert_eq!("link.bandwidth", a.zplc_key());
    }

    #[test]
    fn test_attributes_internal_error() {
        let a1 = Attribute::try_zpr_internal_attr("zdp.role", "admin");
        assert!(a1.is_err());
        let a2 = Attribute::try_zpr_internal_attr("role", "admin");
        assert!(a2.is_err());
    }

    #[test]
    fn test_attributes_internal_error_mv() {
        let a1 = Attribute::try_zpr_internal_attr_mv("zdp.roles", "admin");
        assert!(a1.is_err());
        let a2 = Attribute::try_zpr_internal_attr_mv("roles", "admin");
        assert!(a2.is_err());
    }
}
