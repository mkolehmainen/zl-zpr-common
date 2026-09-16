use crate::policy::v1;
use crate::policy_types::attribute::Attribute;
use crate::policy_types::error::PolicyTypeError;
use crate::policy_types::writer::write_attributes;
use crate::write_to::WriteTo;

pub struct JoinPolicy {
    pub conditions: Vec<Attribute>,
    pub flags: PFlags,
    pub provides: Option<Vec<Service>>,
}

/// Service is part of a join policy.
pub struct Service {
    pub id: String,
    pub endpoints: Vec<Scope>,
    pub kind: ServiceType,
}

/// This struct mirrors what is in the capnp schema.
/// Used in comm policies and join policies.
pub struct Scope {
    pub protocol: u8,
    pub flag: Option<ScopeFlag>,
    pub port: Option<u16>,
    pub port_range: Option<(u16, u16)>,
}

/// This scope flag mirrors what is in the capnp schema.
#[derive(PartialEq, Eq, Debug)]
#[allow(dead_code)]
pub enum ScopeFlag {
    UdpOneWay,
    IcmpRequestReply,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub enum ServiceType {
    #[default]
    Undefined,
    Trusted(String), // Takes the API name
    Authentication,
    Visa,
    Regular,
    BuiltIn, // eg, node access to VS, or VS access to VSS
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Copy)]
pub struct PFlags {
    pub node: bool,
    pub vs: bool,
    pub vs_dock: bool,
}

impl TryFrom<v1::service::Reader<'_>> for Service {
    type Error = PolicyTypeError;

    fn try_from(reader: v1::service::Reader<'_>) -> Result<Self, Self::Error> {
        let id = reader.get_id()?.to_string()?;
        let mut endpoints = Vec::new();
        let endpoint_list = reader.get_endpoints()?;
        for endpoint_reader in endpoint_list.iter() {
            let scope = Scope::try_from(endpoint_reader)?;
            endpoints.push(scope);
        }

        let kind = match reader.get_kind().which()? {
            v1::service::kind::Regular(()) => ServiceType::Regular,
            v1::service::kind::Trusted(name) => ServiceType::Trusted(name?.to_string()?),
            v1::service::kind::Auth(()) => ServiceType::Authentication,
            v1::service::kind::Visa(()) => ServiceType::Visa,
            v1::service::kind::Builtin(()) => ServiceType::BuiltIn,
        };
        Ok(Service {
            id,
            endpoints,
            kind,
        })
    }
}

impl TryFrom<v1::scope::Reader<'_>> for Scope {
    type Error = PolicyTypeError;

    fn try_from(reader: v1::scope::Reader<'_>) -> Result<Self, Self::Error> {
        let protocol = reader.get_protocol();
        let flag = match reader.get_flag() {
            Ok(v1::ScopeFlag::NoFlag) => None,
            Ok(v1::ScopeFlag::UdpOneWay) => Some(ScopeFlag::UdpOneWay),
            Ok(v1::ScopeFlag::IcmpRequestRepl) => Some(ScopeFlag::IcmpRequestReply),
            Err(capnp::NotInSchema(_)) => None,
        };
        let (port, port_range) = match reader.which()? {
            v1::scope::Port(pnum) => (Some(pnum.get_port_num()), None),
            v1::scope::PortRange(pr) => (None, Some((pr.get_low(), pr.get_high()))),
        };
        Ok(Scope {
            protocol,
            flag,
            port,
            port_range,
        })
    }
}

impl PFlags {
    /// Create the set of flags for a node.
    pub fn node(is_vs_dock: bool) -> PFlags {
        PFlags {
            node: true,
            vs: false,
            vs_dock: is_vs_dock,
        }
    }

    /// Create the set of flags for a visa service.
    pub fn vs() -> PFlags {
        PFlags {
            node: false,
            vs: true,
            vs_dock: false,
        }
    }

    pub fn or(&mut self, other: Self) {
        self.node |= other.node;
        self.vs |= other.vs;
        self.vs_dock |= other.vs_dock;
    }

    /// Returns number of "set" flags.
    pub fn count(&self) -> usize {
        let mut count = 0;
        if self.node {
            count += 1;
        }
        if self.vs {
            count += 1;
        }
        if self.vs_dock {
            count += 1;
        }
        count
    }
}

impl WriteTo<v1::j_policy::Builder<'_>> for JoinPolicy {
    fn write_to(&self, bldr: &mut v1::j_policy::Builder) {
        let mut matches_bldr = bldr.reborrow().init_match(self.conditions.len() as u32);
        write_attributes(&self.conditions, &mut matches_bldr);

        if let Some(provides) = &self.provides {
            let mut provides_bldr = bldr.reborrow().init_provides(provides.len() as u32);
            write_services(provides, &mut provides_bldr);
        }

        if self.flags.count() > 0 {
            let mut flags_bldr = bldr.reborrow().init_flags(self.flags.count() as u32);
            let mut idx = 0;
            if self.flags.node {
                flags_bldr.set(idx, v1::JoinFlag::Node);
                idx += 1;
            }
            if self.flags.vs {
                flags_bldr.set(idx, v1::JoinFlag::Vs);
                idx += 1;
            }
            if self.flags.vs_dock {
                flags_bldr.set(idx, v1::JoinFlag::Vsdock);
            }
        }
    }
}

/// Write a services list into capn proto List.
fn write_services(
    services: &[Service],
    builder: &mut capnp::struct_list::Builder<'_, v1::service::Owned>,
) {
    for (i, service) in services.iter().enumerate() {
        let mut s = builder.reborrow().get(i as u32);
        s.set_id(&service.id);
        let mut endpoints = s.reborrow().init_endpoints(service.endpoints.len() as u32);
        for (j, endpoint) in service.endpoints.iter().enumerate() {
            let mut scope_bldr = endpoints.reborrow().get(j as u32);
            scope_bldr.set_protocol(endpoint.protocol as u8);
            if let Some(flowtype) = &endpoint.flag {
                match flowtype {
                    ScopeFlag::IcmpRequestReply => {
                        scope_bldr.set_flag(v1::ScopeFlag::IcmpRequestRepl);
                    }
                    ScopeFlag::UdpOneWay => {
                        scope_bldr.set_flag(v1::ScopeFlag::UdpOneWay);
                    }
                }
            }
            // `port` and `port_range` are independent Options here but a union in the
            // schema, so two of the four Rust states cannot be encoded faithfully:
            //
            //   both set -> `init_port_range` re-sets the union discriminant, so only
            //               the range survives and the port is dropped silently.
            //   neither  -> no discriminant is ever written. It stays 0, which is the
            //               `port` group, and the scope decodes as port 0.
            //
            // Both are covered by tests below. Making the pair a single enum would make
            // the first unrepresentable; the second additionally needs a schema member
            // for "no port" if that is ever a state worth transmitting.
            if let Some(port) = endpoint.port {
                let mut portnum_bldr = scope_bldr.reborrow().init_port();
                portnum_bldr.set_port_num(port);
            }
            if let Some(port_range) = endpoint.port_range {
                let mut port_range_bldr = scope_bldr.reborrow().init_port_range();
                port_range_bldr.set_low(port_range.0);
                port_range_bldr.set_high(port_range.1);
            }
        }
        let mut kind_bldr = s.init_kind();
        match &service.kind {
            ServiceType::Authentication => kind_bldr.set_auth(()),
            ServiceType::Regular => kind_bldr.set_regular(()),
            ServiceType::BuiltIn => kind_bldr.set_builtin(()),
            ServiceType::Visa => kind_bldr.set_visa(()),
            ServiceType::Trusted(name) => kind_bldr.set_trusted(name),
            ServiceType::Undefined => {
                panic!("service with undefined type/kind"); // programming error
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::policy_types::attribute::Attribute;

    fn write_policy(policy: &JoinPolicy) -> capnp::message::Builder<capnp::message::HeapAllocator> {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::j_policy::Builder<'_> = msg.init_root();
            policy.write_to(&mut root);
        }
        msg
    }

    fn policy_with_services(provides: Vec<Service>) -> JoinPolicy {
        JoinPolicy {
            conditions: vec![],
            flags: PFlags::default(),
            provides: Some(provides),
        }
    }

    fn service(kind: ServiceType, endpoints: Vec<Scope>) -> Service {
        Service {
            id: "svc".to_string(),
            endpoints,
            kind,
        }
    }

    fn scope(protocol: u8, flag: Option<ScopeFlag>, port: Option<u16>) -> Scope {
        Scope {
            protocol,
            flag,
            port,
            port_range: None,
        }
    }

    /// Write a policy, then decode its service list back out.
    fn round_trip_services(provides: Vec<Service>) -> Vec<Service> {
        let msg = write_policy(&policy_with_services(provides));
        let reader: v1::j_policy::Reader<'_> = msg.get_root_as_reader().unwrap();
        reader
            .get_provides()
            .unwrap()
            .iter()
            .map(|r| Service::try_from(r).unwrap())
            .collect()
    }

    fn round_trip_one_scope(s: Scope) -> Scope {
        let mut decoded = round_trip_services(vec![service(ServiceType::Regular, vec![s])]);
        decoded.remove(0).endpoints.remove(0)
    }

    fn written_flags(flags: PFlags) -> Vec<v1::JoinFlag> {
        let policy = JoinPolicy {
            conditions: vec![],
            flags,
            provides: None,
        };
        let msg = write_policy(&policy);
        let reader: v1::j_policy::Reader<'_> = msg.get_root_as_reader().unwrap();
        reader
            .get_flags()
            .unwrap()
            .iter()
            .map(|f| f.unwrap())
            .collect()
    }

    // --- Service kinds ---

    #[test]
    fn test_service_kinds_round_trip() {
        let kinds = [
            ServiceType::Regular,
            ServiceType::Authentication,
            ServiceType::Visa,
            ServiceType::BuiltIn,
            ServiceType::Trusted("attrfile".to_string()),
        ];
        let services = kinds
            .iter()
            .map(|k| service(k.clone(), vec![]))
            .collect::<Vec<_>>();

        let decoded = round_trip_services(services);

        assert_eq!(decoded.len(), kinds.len());
        for (got, want) in decoded.iter().zip(kinds.iter()) {
            assert_eq!(got.kind, *want);
            assert_eq!(got.id, "svc");
        }
    }

    #[test]
    fn test_service_preserves_id_and_endpoint_order() {
        let svc = Service {
            id: "ordered".to_string(),
            endpoints: vec![scope(6, None, Some(443)), scope(17, None, Some(53))],
            kind: ServiceType::Regular,
        };

        let decoded = round_trip_services(vec![svc]);

        assert_eq!(decoded[0].id, "ordered");
        assert_eq!(decoded[0].endpoints.len(), 2);
        assert_eq!(decoded[0].endpoints[0].protocol, 6);
        assert_eq!(decoded[0].endpoints[0].port, Some(443));
        assert_eq!(decoded[0].endpoints[1].protocol, 17);
        assert_eq!(decoded[0].endpoints[1].port, Some(53));
    }

    /// `Undefined` is the `Default` variant, so a half-built `Service` reaching the
    /// writer aborts the process rather than erroring.
    #[test]
    #[should_panic(expected = "service with undefined type/kind")]
    fn test_undefined_service_kind_panics_on_write() {
        write_policy(&policy_with_services(vec![service(
            ServiceType::default(),
            vec![],
        )]));
    }

    // --- Scope ---

    #[test]
    fn test_scope_port_round_trips() {
        let decoded = round_trip_one_scope(scope(6, None, Some(8080)));
        assert_eq!(decoded.protocol, 6);
        assert_eq!(decoded.port, Some(8080));
        assert_eq!(decoded.port_range, None);
        assert_eq!(decoded.flag, None);
    }

    #[test]
    fn test_scope_port_range_round_trips() {
        let decoded = round_trip_one_scope(Scope {
            protocol: 17,
            flag: None,
            port: None,
            port_range: Some((1024, 65535)),
        });
        assert_eq!(decoded.protocol, 17);
        assert_eq!(decoded.port, None);
        assert_eq!(decoded.port_range, Some((1024, 65535)));
    }

    #[test]
    fn test_scope_flags_round_trip() {
        // ScopeFlag is not Clone, so build the expected value alongside the input.
        for make in [(|| ScopeFlag::UdpOneWay) as fn() -> ScopeFlag, || {
            ScopeFlag::IcmpRequestReply
        }] {
            let decoded = round_trip_one_scope(scope(1, Some(make()), Some(0)));
            assert_eq!(decoded.flag, Some(make()));
        }
        assert_eq!(round_trip_one_scope(scope(1, None, Some(0))).flag, None);
    }

    /// The wire union has no "neither" state and defaults to `port`, so a scope
    /// carrying no port at all comes back as port 0 rather than as it went in.
    #[test]
    fn test_scope_with_no_port_decodes_as_port_zero() {
        let decoded = round_trip_one_scope(Scope {
            protocol: 6,
            flag: None,
            port: None,
            port_range: None,
        });
        assert_eq!(decoded.port, Some(0));
        assert_eq!(decoded.port_range, None);
    }

    /// `port` and `port_range` are independent `Option`s in Rust but a union on the
    /// wire. Setting both silently keeps only the range, which is written last.
    #[test]
    fn test_scope_with_both_port_and_range_keeps_only_the_range() {
        let decoded = round_trip_one_scope(Scope {
            protocol: 6,
            flag: None,
            port: Some(443),
            port_range: Some((100, 200)),
        });
        assert_eq!(decoded.port, None);
        assert_eq!(decoded.port_range, Some((100, 200)));
    }

    // --- PFlags ---

    #[test]
    fn test_pflags_constructors() {
        let node = PFlags::node(false);
        assert!(node.node && !node.vs && !node.vs_dock);

        let dock = PFlags::node(true);
        assert!(dock.node && !dock.vs && dock.vs_dock);

        let vs = PFlags::vs();
        assert!(!vs.node && vs.vs && !vs.vs_dock);
    }

    #[test]
    fn test_pflags_or_is_a_union() {
        let mut flags = PFlags::node(false);
        flags.or(PFlags::vs());
        assert!(flags.node && flags.vs && !flags.vs_dock);

        // Already-set flags are never cleared.
        flags.or(PFlags::default());
        assert!(flags.node && flags.vs);
    }

    #[test]
    fn test_pflags_count_matches_set_flags() {
        assert_eq!(PFlags::default().count(), 0);
        assert_eq!(PFlags::node(false).count(), 1);
        assert_eq!(PFlags::node(true).count(), 2);
        assert_eq!(
            PFlags {
                node: true,
                vs: true,
                vs_dock: true
            }
            .count(),
            3
        );
    }

    /// The writer sizes the flag list from `count()` and fills it with a separately
    /// tracked index; every combination must produce exactly the expected list.
    #[test]
    fn test_every_flag_combination_is_written() {
        for (node, vs, vs_dock) in [
            (false, false, false),
            (true, false, false),
            (false, true, false),
            (false, false, true),
            (true, true, false),
            (true, false, true),
            (false, true, true),
            (true, true, true),
        ] {
            let flags = PFlags { node, vs, vs_dock };
            let mut expected = Vec::new();
            if node {
                expected.push(v1::JoinFlag::Node);
            }
            if vs {
                expected.push(v1::JoinFlag::Vs);
            }
            if vs_dock {
                expected.push(v1::JoinFlag::Vsdock);
            }

            assert_eq!(
                written_flags(flags),
                expected,
                "flags node={node} vs={vs} vs_dock={vs_dock}"
            );
        }
    }

    // --- JoinPolicy as a whole ---

    #[test]
    fn test_empty_policy_writes_empty_lists() {
        let policy = JoinPolicy {
            conditions: vec![],
            flags: PFlags::default(),
            provides: None,
        };
        let msg = write_policy(&policy);
        let reader: v1::j_policy::Reader<'_> = msg.get_root_as_reader().unwrap();

        assert_eq!(reader.get_match().unwrap().len(), 0);
        assert_eq!(reader.get_provides().unwrap().len(), 0);
        assert_eq!(reader.get_flags().unwrap().len(), 0);
    }

    /// `provides: None` and `provides: Some(vec![])` are indistinguishable on the wire.
    #[test]
    fn test_absent_and_empty_provides_are_equivalent() {
        for provides in [None, Some(vec![])] {
            let policy = JoinPolicy {
                conditions: vec![],
                flags: PFlags::default(),
                provides,
            };
            let msg = write_policy(&policy);
            let reader: v1::j_policy::Reader<'_> = msg.get_root_as_reader().unwrap();
            assert_eq!(reader.get_provides().unwrap().len(), 0);
        }
    }

    #[test]
    fn test_conditions_are_written_in_order() {
        let policy = JoinPolicy {
            conditions: vec![
                Attribute::tag("user.red").build().unwrap(),
                Attribute::tuple("user.role")
                    .single()
                    .value("admin")
                    .build()
                    .unwrap(),
            ],
            flags: PFlags::vs(),
            provides: None,
        };
        let msg = write_policy(&policy);
        let reader: v1::j_policy::Reader<'_> = msg.get_root_as_reader().unwrap();
        let conds = reader.get_match().unwrap();

        assert_eq!(conds.len(), 2);
        assert_eq!(
            conds.get(0).get_key().unwrap().to_str().unwrap(),
            "user.zpr.tag.red"
        );
        assert_eq!(
            conds.get(1).get_key().unwrap().to_str().unwrap(),
            "user.role"
        );
    }
}
