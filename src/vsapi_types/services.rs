use std::net::IpAddr;
use std::time::SystemTime;
use url::Url;

use crate::vsapi::v1;
use crate::vsapi_types::VsapiTypeError;

/// Capnp does not have a separate AuthServicesList structure, instead just uses List(ServiceDescriptor)
#[derive(Debug, Clone)]
pub struct AuthServicesList {
    pub expiration: Option<SystemTime>, // 0 value means "no expiration"
    pub services: Vec<ServiceDescriptor>,
}

/// Service type of a [ServiceDescriptor]. Mirrors `ServiceT` in vs.capnp.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum ServiceT {
    /// On-net actor-authentication service (legacy BAS).
    ActorAuthentication,
    /// Off-net OpenID Connect identity provider.
    OidcAuthentication,
}

/// What a Relying Party needs to talk to an OIDC identity provider. All public data.
/// Mirrors `OidcClientConfig` in vs.capnp.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct OidcClientConfig {
    pub issuer: String,
    pub client_id: String,
    /// `""` on the wire == `None`. Not a secret for public clients (RFC 8252 s8.5).
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    pub allow_offline_access: bool,
}

/// A parsed [vsapi::ServiceDescriptor] that we use to keep ASA records.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ServiceDescriptor {
    pub stype: ServiceT,
    pub service_id: String,
    /// For `OidcAuthentication`: the issuer URL.
    pub service_uri: String,
    /// Unspecified (`::`) for off-net services.
    pub zpr_addr: IpAddr,
    /// Set when `stype == OidcAuthentication`.
    pub oidc: Option<OidcClientConfig>,
}

impl Default for AuthServicesList {
    fn default() -> Self {
        AuthServicesList {
            expiration: Some(SystemTime::UNIX_EPOCH),
            services: Vec::new(),
        }
    }
}

impl AuthServicesList {
    pub fn update(&mut self, expiration: Option<SystemTime>, services: Vec<ServiceDescriptor>) {
        self.expiration = expiration;
        self.services = services;
    }

    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.expiration {
            SystemTime::now() >= exp
        } else {
            false
        }
    }

    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }

    /// The list is "valid" it is non-empty and not expired.
    pub fn is_valid(&self) -> bool {
        !self.is_empty() && !self.is_expired()
    }
}

impl ServiceDescriptor {
    /// Gently try to extract a SocketAddr from this ServiceDescriptor.
    /// If there are any problems, None is returned.
    /// OIDC services are off-net, so they never have a ZPR socket address.
    pub fn get_socket_addr(&self) -> Option<std::net::SocketAddr> {
        if self.stype == ServiceT::OidcAuthentication {
            return None;
        }
        // To create a socket addr we need a port, which is on the URI.
        let uri = match Url::parse(&self.service_uri) {
            Ok(u) => u,
            Err(_) => return None, // Invalid URI
        };
        let port = match uri.port() {
            Some(p) => p,
            None => return None, // No port in URI, so no SocketAddr for you
        };
        Some(std::net::SocketAddr::new(self.zpr_addr.into(), port))
    }
}

impl TryFrom<v1::service_descriptor::Reader<'_>> for ServiceDescriptor {
    type Error = VsapiTypeError;

    fn try_from(reader: v1::service_descriptor::Reader<'_>) -> Result<Self, Self::Error> {
        let svc_id = reader.get_service_id()?.to_string()?;
        let svc_uri = reader.get_service_uri()?.to_string()?;
        let zpr_addr = IpAddr::try_from(reader.get_zpr_addr()?)?;

        let stype = match reader.get_stype()? {
            v1::ServiceT::ActorAuthentication => ServiceT::ActorAuthentication,
            v1::ServiceT::OidcAuthentication => ServiceT::OidcAuthentication,
        };

        // The oidc field is a pointer: absent decodes to None.
        let oidc = if reader.has_oidc() {
            Some(OidcClientConfig::try_from(reader.get_oidc()?)?)
        } else {
            None
        };

        Ok(ServiceDescriptor {
            stype,
            service_id: svc_id,
            service_uri: svc_uri,
            zpr_addr,
            oidc,
        })
    }
}

impl TryFrom<v1::oidc_client_config::Reader<'_>> for OidcClientConfig {
    type Error = VsapiTypeError;

    fn try_from(reader: v1::oidc_client_config::Reader<'_>) -> Result<Self, Self::Error> {
        let mut scopes = Vec::new();
        for s in reader.get_scopes()?.iter() {
            scopes.push(s?.to_string()?);
        }

        // "" on the wire == None (Contract 2).
        let client_secret = reader.get_client_secret()?.to_string()?;
        let client_secret = if client_secret.is_empty() {
            None
        } else {
            Some(client_secret)
        };

        Ok(OidcClientConfig {
            issuer: reader.get_issuer()?.to_string()?,
            client_id: reader.get_client_id()?.to_string()?,
            client_secret,
            scopes,
            allow_offline_access: reader.get_allow_offline_access(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::write_to::WriteTo;
    use std::net::Ipv6Addr;

    /// Round-trip a ServiceDescriptor through capnp.
    fn roundtrip(original: &ServiceDescriptor) -> ServiceDescriptor {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::service_descriptor::Builder<'_> = msg.init_root();
            original.write_to(&mut root);
        }
        let reader: v1::service_descriptor::Reader<'_> = msg.get_root_as_reader().unwrap();
        ServiceDescriptor::try_from(reader).unwrap()
    }

    // --- ServiceDescriptor with stype/oidc (Contract 2) ---

    #[test]
    fn test_service_descriptor_oidc_roundtrip() {
        let original = ServiceDescriptor {
            stype: ServiceT::OidcAuthentication,
            service_id: "google".to_string(),
            service_uri: "https://accounts.google.com".to_string(),
            // Off-net services carry the unspecified address.
            zpr_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            oidc: Some(OidcClientConfig {
                issuer: "https://accounts.google.com".to_string(),
                client_id: "1234-abc.apps.googleusercontent.com".to_string(),
                client_secret: Some("shhh".to_string()),
                scopes: vec!["openid".to_string(), "email".to_string()],
                allow_offline_access: true,
            }),
        };
        assert_eq!(roundtrip(&original), original);
    }

    #[test]
    fn test_service_descriptor_oidc_no_socket_addr() {
        // An OIDC descriptor is off-net: never a socket address, even with a port in the URI.
        let descriptor = ServiceDescriptor {
            stype: ServiceT::OidcAuthentication,
            service_id: "google".to_string(),
            service_uri: "https://accounts.google.com:443/x".to_string(),
            zpr_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            oidc: None,
        };
        assert!(descriptor.get_socket_addr().is_none());
    }

    #[test]
    fn test_service_descriptor_actor_auth_roundtrip() {
        // Legacy descriptors keep working: stype round-trips, oidc stays None.
        let original = ServiceDescriptor {
            stype: ServiceT::ActorAuthentication,
            service_id: "bas".to_string(),
            service_uri: "https://auth.example.com:8443/auth".to_string(),
            zpr_addr: IpAddr::from([192, 168, 1, 100]),
            oidc: None,
        };
        let decoded = roundtrip(&original);
        assert_eq!(decoded, original);
        assert_eq!(
            decoded.get_socket_addr().unwrap().port(),
            8443,
            "ActorAuthentication socket-addr behaviour unchanged"
        );
    }

    #[test]
    fn test_oidc_client_config_empty_secret_decodes_to_none() {
        // "" on the wire == None for clientSecret (Contract 2).
        let original = ServiceDescriptor {
            stype: ServiceT::OidcAuthentication,
            service_id: "google".to_string(),
            service_uri: "https://accounts.google.com".to_string(),
            zpr_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            oidc: Some(OidcClientConfig {
                issuer: "https://accounts.google.com".to_string(),
                client_id: "cid".to_string(),
                client_secret: Some(String::new()),
                scopes: vec![],
                allow_offline_access: false,
            }),
        };
        let decoded = roundtrip(&original);
        assert_eq!(decoded.oidc.as_ref().unwrap().client_secret, None);
    }
}
