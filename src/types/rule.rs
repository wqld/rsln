// // Rule represents a netlink rule.
// type Rule struct {
// 	Priority          int
// 	Family            int
// 	Table             int
// 	Mark              uint32
// 	Mask              *uint32
// 	Tos               uint
// 	TunID             uint
// 	Goto              int
// 	Src               *net.IPNet
// 	Dst               *net.IPNet
// 	Flow              int
// 	IifName           string
// 	OifName           string
// 	SuppressIfgroup   int
// 	SuppressPrefixlen int
// 	Invert            bool
// 	Dport             *RulePortRange
// 	Sport             *RulePortRange
// 	IPProto           int
// 	UIDRange          *RuleUIDRange
// 	Protocol          uint8
// 	Type              uint8
// }

use derive_builder::Builder;
use ipnet::IpNet;

#[derive(Builder)]
#[builder(default)]
pub struct Rule {
    pub priority: i32,
    pub family: i32,
    pub table: i32,
    pub mark: u32,
    pub mask: Option<u32>,
    pub tos: u32,
    pub tun_id: u32,
    pub goto: i32,
    pub src: Option<IpNet>,
    pub dst: Option<IpNet>,
    pub flow: i32,
    pub iif_name: String,
    pub oif_name: String,
    pub suppress_ifgroup: i32,
    pub suppress_prefixlen: i32,
    pub invert: bool,
    pub dport: Option<RulePortRange>,
    pub sport: Option<RulePortRange>,
    pub ip_proto: i32,
    pub uid_range: Option<RuleUIDRange>,
    pub protocol: u8,
    pub rule_type: u8,
}

impl Rule {
    pub fn new() -> Self {
        Self {
            priority: -1,
            goto: -1,
            flow: -1,
            suppress_ifgroup: -1,
            suppress_prefixlen: -1,
            ..Default::default()
        }
    }
}

impl Default for Rule {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RulePortRange {
    pub start: u16,
    pub end: u16,
}

impl RulePortRange {
    pub fn new(start: u16, end: u16) -> Self {
        Self { start, end }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleUIDRange {
    pub start: u32,
    pub end: u32,
}

impl RuleUIDRange {
    pub fn new(start: u32, end: u32) -> Self {
        Self { start, end }
    }
}
