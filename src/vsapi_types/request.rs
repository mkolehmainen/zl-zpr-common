use std::net::IpAddr;

use crate::vsapi::v1;
use crate::vsapi_types::AuthBlob;
use crate::vsapi_types::KeyFormat;
use crate::vsapi_types::PacketDesc;
use crate::vsapi_types::Param;
use crate::vsapi_types::VsapiTypeError;

/// Request to connect to VS
#[derive(Debug)]
pub struct ConnectRequest {
    pub blobs: Vec<AuthBlob>,
    pub claims: Vec<Claim>,
    pub substrate_addr: IpAddr,
    pub dock_interface: u8,
    pub a2a_dh_public_key: PublicKey,
}

/// Request to reauthorize an existing connection with fresh credentials.
/// Mirrors `ReauthRequest` in vs.capnp.
#[derive(Debug)]
pub struct ReauthRequest {
    pub zpr_addr: IpAddr,
    pub blobs: Vec<AuthBlob>,
}

/// Wraps the Cap'n Proto `VSConnT` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectType {
    Reset,
    Reconnect,
}

#[derive(Debug)]
pub struct VSConnectRequest {
    pub cn: String,
    pub ctype: ConnectType,
    pub params: Option<Vec<Param>>,
}

#[derive(Debug)]
pub struct Claim {
    pub key: String,
    pub value: String,
}

impl Claim {
    pub fn new(key: String, value: String) -> Self {
        Self { key, value }
    }
}

#[derive(Default, Debug, Clone)]
pub struct PublicKey {
    pub format: KeyFormat,
    pub public_key: Vec<u8>,
}

impl PublicKey {
    pub fn new(key: &[u8]) -> Self {
        PublicKey {
            format: KeyFormat::default(),
            public_key: key.to_vec(),
        }
    }
}

#[derive(Debug)]
pub struct VisaRequest {
    pub pdesc: PacketDesc,
    pub previous_id: Option<u64>,
}

impl TryFrom<v1::connect_request::Reader<'_>> for ConnectRequest {
    type Error = VsapiTypeError;

    fn try_from(reader: v1::connect_request::Reader<'_>) -> Result<Self, Self::Error> {
        let dock_interface = reader.get_dock_interface();
        let substrate_addr = IpAddr::try_from(reader.get_substrate_addr()?)?;

        let mut blobs = Vec::new();
        let blob_readers = reader.get_blobs()?;
        for blob_reader in blob_readers.iter() {
            let blob = AuthBlob::try_from(blob_reader)?;
            blobs.push(blob);
        }

        let mut claims = Vec::new();
        let claim_readers = reader.get_claims()?;
        for claim_reader in claim_readers.iter() {
            let claim = Claim::try_from(claim_reader)?;
            claims.push(claim);
        }
        let a2a_dh_public_key = PublicKey::try_from(reader.get_a2a_dh_public_key()?)?;

        Ok(ConnectRequest {
            blobs,
            claims,
            substrate_addr,
            dock_interface,
            a2a_dh_public_key,
        })
    }
}

impl TryFrom<v1::reauth_request::Reader<'_>> for ReauthRequest {
    type Error = VsapiTypeError;

    fn try_from(reader: v1::reauth_request::Reader<'_>) -> Result<Self, Self::Error> {
        let zpr_addr = IpAddr::try_from(reader.get_zpr_addr()?)?;

        let mut blobs = Vec::new();
        let blob_readers = reader.get_blobs()?;
        for blob_reader in blob_readers.iter() {
            let blob = AuthBlob::try_from(blob_reader)?;
            blobs.push(blob);
        }

        Ok(ReauthRequest { zpr_addr, blobs })
    }
}

impl TryFrom<v1::v_s_connect_request::Reader<'_>> for VSConnectRequest {
    type Error = VsapiTypeError;

    fn try_from(reader: v1::v_s_connect_request::Reader<'_>) -> Result<Self, Self::Error> {
        let cn = reader.get_cn()?.to_string()?;
        let ctype = ConnectType::from(reader.get_ctype()?);
        let params = {
            if reader.has_params() {
                let mut params = Vec::new();
                let param_readers = reader.get_params()?;
                for param_reader in param_readers.iter() {
                    let param = Param::try_from(param_reader)?;
                    params.push(param);
                }
                Some(params)
            } else {
                None
            }
        };

        Ok(VSConnectRequest { cn, ctype, params })
    }
}

impl TryFrom<v1::public_key::Reader<'_>> for PublicKey {
    type Error = VsapiTypeError;

    /// Returns err if required values are not set
    fn try_from(reader: v1::public_key::Reader) -> Result<Self, Self::Error> {
        let format = match reader.get_format()? {
            v1::KeyFormat::ZprKF01 => KeyFormat::ZprKF01,
        };
        let public_key = reader.get_public_key()?.to_vec();

        Ok(Self { format, public_key })
    }
}

impl From<v1::VSConnT> for ConnectType {
    fn from(value: v1::VSConnT) -> Self {
        match value {
            v1::VSConnT::Reset => ConnectType::Reset,
            v1::VSConnT::Reconnect => ConnectType::Reconnect,
        }
    }
}

impl From<ConnectType> for v1::VSConnT {
    fn from(value: ConnectType) -> Self {
        match value {
            ConnectType::Reset => v1::VSConnT::Reset,
            ConnectType::Reconnect => v1::VSConnT::Reconnect,
        }
    }
}

impl TryFrom<v1::claim::Reader<'_>> for Claim {
    type Error = VsapiTypeError;

    fn try_from(reader: v1::claim::Reader<'_>) -> Result<Self, Self::Error> {
        let key = reader.get_key()?.to_string()?;
        let value = reader.get_value()?.to_string()?;
        Ok(Claim { key, value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vsapi_types::{OidcBlob, ParamValue};
    use crate::write_to::WriteTo;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_vs_connect_request_msg(
        cn: &str,
        ctype: v1::VSConnT,
        params: &[Param],
    ) -> capnp::message::Builder<capnp::message::HeapAllocator> {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::v_s_connect_request::Builder<'_> = msg.init_root();
            root.set_cn(cn);
            root.set_ctype(ctype);
            if !params.is_empty() {
                let mut params_bldr = root.reborrow().init_params(params.len() as u32);
                for (i, param) in params.iter().enumerate() {
                    let mut param_bldr = params_bldr.reborrow().get(i as u32);
                    param.write_to(&mut param_bldr);
                }
            }
        }
        msg
    }

    fn read_vs_connect_request(
        msg: &capnp::message::Builder<capnp::message::HeapAllocator>,
    ) -> VSConnectRequest {
        let reader: v1::v_s_connect_request::Reader<'_> = msg.get_root_as_reader().unwrap();
        VSConnectRequest::try_from(reader).unwrap()
    }

    fn roundtrip_vs_connect_request(req: &VSConnectRequest) -> VSConnectRequest {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::v_s_connect_request::Builder<'_> = msg.init_root();
            req.write_to(&mut root);
        }
        read_vs_connect_request(&msg)
    }

    #[test]
    fn vs_connect_request_tryfrom_reset_without_params() {
        let msg = make_vs_connect_request_msg("actor.example", v1::VSConnT::Reset, &[]);
        let req = read_vs_connect_request(&msg);

        assert_eq!(req.cn, "actor.example");
        assert_eq!(req.ctype, ConnectType::Reset);
        assert!(req.params.is_none());
    }

    #[test]
    fn vs_connect_request_tryfrom_reconnect_with_params() {
        let params = vec![
            Param::new_str("mode".to_string(), "bootstrap".to_string()),
            Param::new_u64("generation".to_string(), 42),
            Param::new_ip(
                "zpr_addr".to_string(),
                IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)),
            ),
        ];
        let msg = make_vs_connect_request_msg("actor.example", v1::VSConnT::Reconnect, &params);
        let req = read_vs_connect_request(&msg);

        assert_eq!(req.cn, "actor.example");
        assert_eq!(req.ctype, ConnectType::Reconnect);
        assert!(req.params.is_some());
        let params = req.params.as_ref().unwrap();
        assert_eq!(params.len(), 3);
        assert!(matches!(
            params[0].value,
            ParamValue::StrParam(ref value) if value == "bootstrap"
        ));
        assert!(matches!(params[1].value, ParamValue::U64Param(42)));
        assert!(matches!(
            params[2].value,
            ParamValue::IpParam(IpAddr::V4(addr)) if addr == Ipv4Addr::new(10, 20, 30, 40)
        ));
    }

    #[test]
    fn vs_connect_request_roundtrip_reset_without_params() {
        let original = VSConnectRequest {
            cn: "actor.example".to_string(),
            ctype: ConnectType::Reset,
            params: None,
        };
        let result = roundtrip_vs_connect_request(&original);

        assert_eq!(result.cn, original.cn);
        assert_eq!(result.ctype, original.ctype);
        assert!(result.params.is_none());
    }

    #[test]
    fn vs_connect_request_roundtrip_reconnect_with_params() {
        let original = VSConnectRequest {
            cn: "actor.example".to_string(),
            ctype: ConnectType::Reconnect,
            params: Some(vec![
                Param::new_str("mode".to_string(), "resume".to_string()),
                Param::new_u64("generation".to_string(), u64::MAX),
            ]),
        };
        let result = roundtrip_vs_connect_request(&original);

        assert_eq!(result.cn, original.cn);
        assert_eq!(result.ctype, original.ctype);
        assert!(result.params.is_some());
        let params = result.params.as_ref().unwrap();
        assert_eq!(params.len(), 2);
        assert!(matches!(
            params[0].value,
            ParamValue::StrParam(ref value) if value == "resume"
        ));
        assert!(matches!(params[1].value, ParamValue::U64Param(u64::MAX)));
    }

    fn make_reauth_request_msg(
        zpr_addr: IpAddr,
        oidc_blobs: &[OidcBlob],
    ) -> capnp::message::Builder<capnp::message::HeapAllocator> {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::reauth_request::Builder<'_> = msg.init_root();
            {
                let mut ip_bldr = root.reborrow().init_zpr_addr();
                zpr_addr.write_to(&mut ip_bldr);
            }
            let mut blobs_bldr = root.reborrow().init_blobs(oidc_blobs.len() as u32);
            for (i, oidc) in oidc_blobs.iter().enumerate() {
                let mut oidc_bldr = blobs_bldr.reborrow().get(i as u32).init_oidc();
                oidc_bldr.set_issuer(&oidc.issuer);
                oidc_bldr.set_id_token(&oidc.id_token);
                oidc_bldr.set_nonce(&oidc.nonce);
            }
        }
        msg
    }

    fn read_reauth_request(
        msg: &capnp::message::Builder<capnp::message::HeapAllocator>,
    ) -> ReauthRequest {
        let reader: v1::reauth_request::Reader<'_> = msg.get_root_as_reader().unwrap();
        ReauthRequest::try_from(reader).unwrap()
    }

    #[test]
    fn reauth_request_tryfrom_v4_single_oidc_blob() {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40));
        let oidc = OidcBlob {
            issuer: "https://accounts.google.com".to_string(),
            id_token: "eyJhbG...load.sig".to_string(),
            nonce: "expected-nonce-hash".to_string(),
        };
        let msg = make_reauth_request_msg(addr, std::slice::from_ref(&oidc));
        let req = read_reauth_request(&msg);

        assert_eq!(req.zpr_addr, addr);
        assert_eq!(req.blobs.len(), 1);
        match &req.blobs[0] {
            AuthBlob::Oidc(got) => {
                assert_eq!(got.issuer, oidc.issuer);
                assert_eq!(got.id_token, oidc.id_token);
                assert_eq!(got.nonce, oidc.nonce);
            }
            other => panic!("expected AuthBlob::Oidc, got {other:?}"),
        }
    }

    #[test]
    fn reauth_request_tryfrom_v6_multiple_blobs() {
        let addr: IpAddr = "2001:db8::1".parse().unwrap();
        let blobs = vec![
            OidcBlob {
                issuer: "https://issuer-one.example".to_string(),
                id_token: "token-one".to_string(),
                nonce: "nonce-one".to_string(),
            },
            OidcBlob {
                issuer: "https://issuer-two.example".to_string(),
                id_token: "token-two".to_string(),
                nonce: "nonce-two".to_string(),
            },
        ];
        let msg = make_reauth_request_msg(addr, &blobs);
        let req = read_reauth_request(&msg);

        assert_eq!(req.zpr_addr, addr);
        assert_eq!(req.blobs.len(), 2);
        for (got, want) in req.blobs.iter().zip(blobs.iter()) {
            match got {
                AuthBlob::Oidc(oidc) => {
                    assert_eq!(oidc.issuer, want.issuer);
                    assert_eq!(oidc.id_token, want.id_token);
                    assert_eq!(oidc.nonce, want.nonce);
                }
                other => panic!("expected AuthBlob::Oidc, got {other:?}"),
            }
        }
    }

    #[test]
    fn reauth_request_tryfrom_empty_blobs() {
        // Blob-count policy is the VS handler's job (zipline#43); the wrapper
        // accepts an empty list without error.
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let msg = make_reauth_request_msg(addr, &[]);
        let req = read_reauth_request(&msg);

        assert_eq!(req.zpr_addr, addr);
        assert!(req.blobs.is_empty());
    }

    #[test]
    fn connect_request_roundtrip_with_a2a_dh_public_key() {
        let key = [7u8; 32];
        let original = ConnectRequest {
            blobs: Vec::new(),
            claims: Vec::new(),
            substrate_addr: IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)),
            dock_interface: 1,
            a2a_dh_public_key: PublicKey::new(&key),
        };

        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::connect_request::Builder<'_> = msg.init_root();
            original.write_to(&mut root);
        }
        let reader: v1::connect_request::Reader<'_> = msg.get_root_as_reader().unwrap();
        let result = ConnectRequest::try_from(reader).unwrap();

        assert_eq!(result.a2a_dh_public_key.public_key, key);
        assert!(matches!(
            result.a2a_dh_public_key.format,
            KeyFormat::ZprKF01
        ));
    }
}
