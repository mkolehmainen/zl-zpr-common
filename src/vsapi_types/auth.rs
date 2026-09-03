use std::net::IpAddr;

use crate::vsapi::v1;

/// Blob passed with a ConnectRequest
#[derive(Debug)]
pub enum AuthBlob {
    SS(SelfSignedBlob),
    AC(AuthCodeBlob),
    Oidc(OidcBlob),
}

#[derive(Debug, Default)]
pub struct SelfSignedBlob {
    pub alg: ChallengeAlg,
    pub challenge: Vec<u8>,
    pub cn: String,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug)]
pub struct AuthCodeBlob {
    pub asa_addr: IpAddr,
    pub code: String,
    pub pkce: String,
    pub client_id: String,
}

/// OIDC authentication blob: an `id_token` to validate against the trusted service
/// declared for `issuer`. Mirrors `OidcBlob` in vs.capnp.
#[derive(Debug, Clone)]
pub struct OidcBlob {
    /// Selector: which declared trusted service to validate against. Never a trust input.
    pub issuer: String,
    /// The JWT, verbatim.
    pub id_token: String,
    /// Expected `nonce` claim; the node has verified its freshness.
    pub nonce: String,
}

#[derive(Debug, Default)]
pub enum ChallengeAlg {
    #[default]
    RsaSha256Pkcs1v15,
}

impl TryFrom<v1::auth_blob::Reader<'_>> for AuthBlob {
    type Error = crate::vsapi_types::VsapiTypeError;

    fn try_from(reader: v1::auth_blob::Reader<'_>) -> Result<Self, Self::Error> {
        match reader.which()? {
            v1::auth_blob::Which::Ss(ss_blob_reader) => {
                let ss_blob_reader = ss_blob_reader?;
                let ss_blob = SelfSignedBlob::try_from(ss_blob_reader)?;
                Ok(AuthBlob::SS(ss_blob))
            }
            v1::auth_blob::Which::Ac(ac_blob_reader) => {
                let ac_blob_reader = ac_blob_reader?;
                let ac_blob = AuthCodeBlob::try_from(ac_blob_reader)?;
                Ok(AuthBlob::AC(ac_blob))
            }
            v1::auth_blob::Which::Oidc(oidc_blob_reader) => {
                let oidc_blob_reader = oidc_blob_reader?;
                let oidc_blob = OidcBlob::try_from(oidc_blob_reader)?;
                Ok(AuthBlob::Oidc(oidc_blob))
            }
        }
    }
}

impl TryFrom<v1::oidc_blob::Reader<'_>> for OidcBlob {
    type Error = crate::vsapi_types::VsapiTypeError;

    fn try_from(reader: v1::oidc_blob::Reader<'_>) -> Result<Self, Self::Error> {
        Ok(OidcBlob {
            issuer: reader.get_issuer()?.to_string()?,
            id_token: reader.get_id_token()?.to_string()?,
            nonce: reader.get_nonce()?.to_string()?,
        })
    }
}

impl TryFrom<v1::self_signed_blob::Reader<'_>> for SelfSignedBlob {
    type Error = crate::vsapi_types::VsapiTypeError;

    fn try_from(reader: v1::self_signed_blob::Reader<'_>) -> Result<Self, Self::Error> {
        let alg = match reader.get_alg()? {
            v1::ChallengeAlg::RsaSha256Pkcs1v15 => ChallengeAlg::RsaSha256Pkcs1v15,
        };
        Ok(SelfSignedBlob {
            alg,
            challenge: reader.get_challenge()?.to_vec(),
            cn: reader.get_cn()?.to_string()?,
            timestamp: reader.get_timestamp(),
            signature: reader.get_signature()?.to_vec(),
        })
    }
}

impl TryFrom<v1::auth_code_blob::Reader<'_>> for AuthCodeBlob {
    type Error = crate::vsapi_types::VsapiTypeError;

    fn try_from(reader: v1::auth_code_blob::Reader<'_>) -> Result<Self, Self::Error> {
        let asa_addr = IpAddr::try_from(reader.get_asa_addr()?)?;
        Ok(AuthCodeBlob {
            asa_addr,
            code: reader.get_code()?.to_string()?,
            pkce: reader.get_pkce()?.to_string()?,
            client_id: reader.get_client_id()?.to_string()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::write_to::WriteTo;

    // --- AuthBlob::Oidc round-trip (Contract 2) ---

    #[test]
    fn test_auth_blob_oidc_roundtrip() {
        let original = AuthBlob::Oidc(OidcBlob {
            issuer: "https://accounts.google.com".to_string(),
            id_token: "eyJhbGciOiJSUzI1NiJ9.payload.sig".to_string(),
            nonce: "expected-nonce-hash".to_string(),
        });
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::auth_blob::Builder<'_> = msg.init_root();
            original.write_to(&mut root);
        }
        let reader: v1::auth_blob::Reader<'_> = msg.get_root_as_reader().unwrap();
        let decoded = AuthBlob::try_from(reader).unwrap();
        match decoded {
            AuthBlob::Oidc(oidc) => {
                assert_eq!(oidc.issuer, "https://accounts.google.com");
                assert_eq!(oidc.id_token, "eyJhbGciOiJSUzI1NiJ9.payload.sig");
                assert_eq!(oidc.nonce, "expected-nonce-hash");
            }
            other => panic!("expected AuthBlob::Oidc, got {other:?}"),
        }
    }

    #[test]
    fn test_auth_blob_ss_roundtrip_unchanged() {
        // Existing SS blob behaviour must be unaffected by the OIDC variant.
        let original = AuthBlob::SS(SelfSignedBlob {
            alg: ChallengeAlg::RsaSha256Pkcs1v15,
            challenge: vec![1, 2, 3],
            cn: "laptop1.zpr".to_string(),
            timestamp: 1756850000,
            signature: vec![4, 5, 6],
        });
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::auth_blob::Builder<'_> = msg.init_root();
            original.write_to(&mut root);
        }
        let reader: v1::auth_blob::Reader<'_> = msg.get_root_as_reader().unwrap();
        match AuthBlob::try_from(reader).unwrap() {
            AuthBlob::SS(ss) => {
                assert_eq!(ss.cn, "laptop1.zpr");
                assert_eq!(ss.challenge, vec![1, 2, 3]);
                assert_eq!(ss.timestamp, 1756850000);
                assert_eq!(ss.signature, vec![4, 5, 6]);
            }
            other => panic!("expected AuthBlob::SS, got {other:?}"),
        }
    }
}
