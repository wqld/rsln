use anyhow::{bail, Result};
use ipnet::IpNet;
use std::ops::{Deref, DerefMut};

use crate::{
    core::message::Message,
    handle::handle::SocketHandle,
    types::{
        message::{Attribute, RouteAttr, RouteMessage},
        rule::Rule,
    },
};

const FIB_RULE_INVERT: u32 = 0x2;

pub struct RuleHandle<'a> {
    pub socket: &'a mut SocketHandle,
}

impl<'a> Deref for RuleHandle<'a> {
    type Target = SocketHandle;

    fn deref(&self) -> &Self::Target {
        self.socket
    }
}

impl DerefMut for RuleHandle<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.socket
    }
}

impl<'a> From<&'a mut SocketHandle> for RuleHandle<'a> {
    fn from(socket: &'a mut SocketHandle) -> Self {
        Self { socket }
    }
}

impl RuleHandle<'_> {
    fn handle(&mut self, rule: &Rule, proto: u16, flags: i32) -> Result<()> {
        let mut req = Message::new(proto, flags);
        let mut msg = RouteMessage::new();

        msg.family = libc::AF_INET as u8;
        msg.protocol = libc::RTPROT_BOOT;
        msg.scope = libc::RT_SCOPE_UNIVERSE;
        msg.table = libc::RT_TABLE_UNSPEC;
        msg.route_type = rule.rule_type;

        if msg.route_type == 0 && (flags as u32 & libc::NLM_F_CREATE as u32) > 0 {
            msg.route_type = libc::RTN_UNICAST;
        }

        if rule.invert {
            msg.flags |= FIB_RULE_INVERT;
        }

        if rule.family != 0 {
            msg.family = rule.family as u8;
        }

        if rule.table >= 0 && rule.table < 256 {
            msg.table = rule.table as u8;
        }

        if rule.tos != 0 {
            msg.tos = rule.tos as u8;
        }

        let mut attrs = vec![];
        let mut dst_family = 0;

        if let Some(dst) = rule.dst {
            let (family, dst_data) = match dst {
                IpNet::V4(ip) => (libc::AF_INET, ip.addr().octets().to_vec()),
                IpNet::V6(ip) => (libc::AF_INET6, ip.addr().octets().to_vec()),
            };

            msg.dst_len = dst.prefix_len();
            msg.family = family as u8;
            dst_family = family;

            attrs.push(RouteAttr::new(libc::RTA_DST, &dst_data));
        }

        if let Some(src) = rule.src {
            let (family, src_data) = match src {
                IpNet::V4(ip) => (libc::AF_INET, ip.addr().octets().to_vec()),
                IpNet::V6(ip) => (libc::AF_INET6, ip.addr().octets().to_vec()),
            };
            msg.src_len = src.prefix_len();
            msg.family = family as u8;

            if dst_family != 0 && dst_family != family {
                bail!("source and destination ip are not the same IP family");
            }

            attrs.push(RouteAttr::new(libc::RTA_SRC, &src_data));
        }

        if rule.priority >= 0 {
            attrs.push(RouteAttr::new(6, &rule.priority.to_ne_bytes()));
        }

        if rule.mark != 0 || rule.mask.is_some() {
            attrs.push(RouteAttr::new(10, &rule.mark.to_ne_bytes()));
        }
        if let Some(mask) = rule.mask {
            attrs.push(RouteAttr::new(10, &mask.to_ne_bytes()));
        }

        if rule.flow >= 0 {
            attrs.push(RouteAttr::new(11, &(rule.flow as u32).to_ne_bytes()));
        }

        if rule.tun_id > 0 {
            attrs.push(RouteAttr::new(12, &(rule.tun_id as u32).to_ne_bytes()));
        }

        if rule.table >= 256 {
            attrs.push(RouteAttr::new(15, &(rule.table as u32).to_ne_bytes()));
        }
        if msg.table > 0 {
            if rule.suppress_prefixlen >= 0 {
                attrs.push(RouteAttr::new(
                    14,
                    &(rule.suppress_prefixlen as u32).to_ne_bytes(),
                ));
            }
            if rule.suppress_ifgroup >= 0 {
                attrs.push(RouteAttr::new(
                    13,
                    &(rule.suppress_ifgroup as u32).to_ne_bytes(),
                ));
            }
        }

        if !rule.iif_name.is_empty() {
            let iif_name = rule.iif_name.clone();
            attrs.push(RouteAttr::new(3, iif_name.as_bytes()));
        }
        if !rule.oif_name.is_empty() {
            let oif_name = rule.oif_name.clone();
            attrs.push(RouteAttr::new(17, oif_name.as_bytes()));
        }

        if rule.goto >= 0 {
            msg.route_type = 2;
            attrs.push(RouteAttr::new(4, &(rule.goto as u32).to_ne_bytes()));
        }

        if rule.ip_proto > 0 {
            attrs.push(RouteAttr::new(22, &(rule.ip_proto as u32).to_ne_bytes()));
        }

        if let Some(dport) = &rule.dport {
            let mut b = Vec::with_capacity(4);
            b.extend_from_slice(&dport.start.to_ne_bytes());
            b.extend_from_slice(&dport.end.to_ne_bytes());
            attrs.push(RouteAttr::new(24, &b));
        }

        if let Some(sport) = &rule.sport {
            let mut b = Vec::with_capacity(4);
            b.extend_from_slice(&sport.start.to_ne_bytes());
            b.extend_from_slice(&sport.end.to_ne_bytes());
            attrs.push(RouteAttr::new(23, &b));
        }

        if let Some(uid_range) = &rule.uid_range {
            let mut b = Vec::with_capacity(8);
            b.extend_from_slice(&uid_range.start.to_ne_bytes());
            b.extend_from_slice(&uid_range.end.to_ne_bytes());
            attrs.push(RouteAttr::new(20, &b));
        }

        if rule.protocol > 0 {
            attrs.push(RouteAttr::new(21, &[rule.protocol]));
        }

        req.add(&msg.serialize()?);
        for attr in attrs {
            req.add(&attr.serialize()?);
        }

        self.request(&mut req, 0)?;
        Ok(())
    }

    pub fn add(&mut self, rule: &Rule) -> Result<()> {
        self.handle(
            rule,
            libc::RTM_NEWRULE,
            libc::NLM_F_CREATE | libc::NLM_F_EXCL | libc::NLM_F_ACK,
        )
    }

    pub fn del(&mut self, rule: &Rule) -> Result<()> {
        self.handle(rule, libc::RTM_DELRULE, libc::NLM_F_ACK)
    }
}
