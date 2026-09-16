use crate::vsapi_types::VsapiTypeError;
use std::net::IpAddr;

/// Create an ip address from a Vector, or return an error if the vector is badly formatted
pub fn ip_addr_from_vec(v: Vec<u8>) -> Result<IpAddr, VsapiTypeError> {
    match v.len() {
        4 => Ok(IpAddr::from(<[u8; 4]>::try_from(v.as_slice())?)),
        16 => Ok(IpAddr::from(<[u8; 16]>::try_from(v.as_slice())?)),
        _ => Err(VsapiTypeError::DeserializationError(
            "Bad IP Address format",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn four_bytes_becomes_ipv4() {
        let addr = ip_addr_from_vec(vec![192, 168, 1, 1]).expect("4 bytes is a valid v4 address");
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn sixteen_bytes_becomes_ipv6() {
        let mut bytes = vec![0u8; 16];
        bytes[0] = 0xfd;
        bytes[1] = 0x5a;
        bytes[15] = 0x42;

        let addr = ip_addr_from_vec(bytes).expect("16 bytes is a valid v6 address");

        assert_eq!(
            addr,
            IpAddr::V6(Ipv6Addr::new(0xfd5a, 0, 0, 0, 0, 0, 0, 0x42))
        );
    }

    #[test]
    fn all_zero_bytes_are_accepted() {
        assert_eq!(
            ip_addr_from_vec(vec![0; 4]).expect("unspecified v4 is still well formed"),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
        assert_eq!(
            ip_addr_from_vec(vec![0; 16]).expect("unspecified v6 is still well formed"),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        );
    }

    /// Any length other than 4 or 16 is an error, never a panic — including the
    /// off-by-one lengths either side of each valid width.
    #[test]
    fn other_lengths_are_rejected() {
        for len in [0, 1, 3, 5, 6, 8, 15, 17, 32] {
            let err = ip_addr_from_vec(vec![0; len])
                .expect_err(&format!("{len} bytes is not an address"));
            assert!(
                matches!(err, VsapiTypeError::DeserializationError(_)),
                "{len} bytes gave unexpected error: {err:?}"
            );
        }
    }
}
