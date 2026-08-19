use crate::policy::v1;
use crate::policy_types::attribute::Attribute;

/// Helper to write attributes into capnp AttrExpr list.
/// We have to do this for client conditions and service conditions.
pub fn write_attributes(
    attrs: &[Attribute],
    conds: &mut capnp::struct_list::Builder<'_, v1::attr_expr::Owned>,
) {
    for (j, attr) in attrs.iter().enumerate() {
        let mut ccond = conds.reborrow().get(j as u32);
        // foo:fee    (foo, eq, fee)
        // foo:       (foo, has, "")
        ccond.set_key(&attr.zpl_key());
        let vals = attr.zpl_values();

        if vals.is_empty() || vals[0].is_empty() || attr.is_multi_valued() {
            ccond.set_op(v1::AttrOp::Has);
        } else {
            ccond.set_op(v1::AttrOp::Eq);
        }
        let mut cvals = ccond.init_value(vals.len() as u32);
        for (i, val) in vals.iter().enumerate() {
            cvals.set(i as u32, val);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::policy_types::attr_exp::AttrExp;
    use crate::policy_types::attr_exp::AttrOp;

    fn write_and_read_one(attr: &Attribute) -> AttrExp {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut list: capnp::struct_list::Builder<'_, v1::attr_expr::Owned> =
                msg.init_root::<capnp::any_pointer::Builder>().initn_as(1);
            write_attributes(std::slice::from_ref(attr), &mut list);
        }
        let reader: capnp::struct_list::Reader<'_, v1::attr_expr::Owned> = msg
            .get_root_as_reader::<capnp::any_pointer::Reader>()
            .unwrap()
            .get_as()
            .unwrap();
        AttrExp::try_from(reader.get(0)).unwrap()
    }

    #[test]
    fn test_write_tag_is_valueless_has() {
        let tag = Attribute::tag("user.red").build().unwrap();
        let exp = write_and_read_one(&tag);
        assert_eq!(exp.key, "user.zpr.tag.red");
        assert_eq!(exp.op, AttrOp::Has);
        assert!(exp.value.is_empty());
    }

    #[test]
    fn test_write_single_valued_is_eq() {
        let attr = Attribute::tuple("user.role")
            .single()
            .value("admin")
            .build()
            .unwrap();
        let exp = write_and_read_one(&attr);
        assert_eq!(exp.key, "user.role");
        assert_eq!(exp.op, AttrOp::Eq);
        assert_eq!(exp.value, vec!["admin"]);
    }
}
