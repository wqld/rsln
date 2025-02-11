use std::net::{IpAddr, Ipv4Addr};

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use super::message::{Attribute, RouteAttrs};

const INET_DIAG_MEMINFO: u8 = 1;
const INET_DIAG_INFO: u8 = 2;
const INET_DIAG_VEGASINFO: u8 = 3;
const INET_DIAG_BBRINFO: u8 = 16;

#[repr(C)]
#[derive(Serialize, Default)]
pub struct SockDiagReq {
    family: u8,
    protocol: u8,
    ext: u8,
    pad: u8,
    states: u32,
    id: SockDiagId,
}

impl Attribute for SockDiagReq {
    fn len(&self) -> usize {
        Self::LEN
    }

    fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(Self::LEN);

        buf.push(self.family);
        buf.push(self.protocol);
        buf.push(self.ext);
        buf.push(self.pad);
        buf.extend_from_slice(&self.states.to_ne_bytes());
        buf.extend_from_slice(&self.id.src_port.to_be_bytes());
        buf.extend_from_slice(&self.id.dst_port.to_be_bytes());

        let (src_octets, dst_octets) = match (self.id.src_ip, self.id.dst_ip) {
            (IpAddr::V4(src_v4), IpAddr::V4(dst_v4)) => {
                let (mut src_octets, mut dst_octets) = ([0u8; 16], [0u8; 16]);
                src_octets[12..16].copy_from_slice(&src_v4.octets());
                dst_octets[12..16].copy_from_slice(&dst_v4.octets());
                (src_octets, dst_octets)
            }
            (IpAddr::V6(src_v6), IpAddr::V6(dst_v6)) => (src_v6.octets(), dst_v6.octets()),
            _ => bail!("invaild"),
        };

        buf.extend_from_slice(&src_octets);
        buf.extend_from_slice(&dst_octets);
        buf.extend_from_slice(&self.id.interface.to_ne_bytes());
        buf.extend_from_slice(&self.id.cookie[0].to_ne_bytes());
        buf.extend_from_slice(&self.id.cookie[1].to_ne_bytes());

        Ok(buf)
    }
}

impl SockDiagReq {
    const LEN: usize = SockDiagId::LEN + 8;

    pub fn request_tcp_info(family: u8) -> Self {
        Self {
            family,
            protocol: libc::IPPROTO_TCP as u8,
            ext: (1 << (INET_DIAG_VEGASINFO - 1)) | (1 << (INET_DIAG_INFO - 1)),
            pad: 0,
            states: 0xfff,
            id: SockDiagId::default(),
        }
    }

    pub fn request_udp_info(family: u8) -> Self {
        Self {
            family,
            protocol: libc::IPPROTO_UDP as u8,
            ext: (1 << (INET_DIAG_VEGASINFO - 1))
                | (1 << (INET_DIAG_INFO - 1))
                | (1 << (INET_DIAG_MEMINFO - 1)),
            pad: 0,
            states: 0xfff,
            id: SockDiagId::default(),
        }
    }
}

#[derive(Default, Debug)]
pub struct InetDiagTcpResp {
    pub msg: SockDiag,
    pub tcp_diag: TcpDiag,
    pub tcp_bbr: TcpBbrDiag,
}

impl From<&[u8]> for InetDiagTcpResp {
    fn from(buf: &[u8]) -> Self {
        let msg = SockDiag::deserialize(buf).unwrap();
        let attrs = RouteAttrs::from(&buf[SockDiag::LEN..]);

        let mut resp = InetDiagTcpResp {
            msg,
            ..Default::default()
        };

        for attr in attrs {
            match attr.header.rta_type as u8 {
                INET_DIAG_INFO => resp.tcp_diag = bincode::deserialize(&attr.payload).unwrap(),
                INET_DIAG_BBRINFO => resp.tcp_bbr = bincode::deserialize(&attr.payload).unwrap(),
                _ => {}
            }
        }

        resp
    }
}

#[derive(Default, Debug)]
pub struct InetDiagUdpResp {
    pub msg: SockDiag,
    pub memory: Memory,
}

impl From<&[u8]> for InetDiagUdpResp {
    fn from(buf: &[u8]) -> Self {
        let msg = SockDiag::deserialize(buf).unwrap();
        let attrs = RouteAttrs::from(&buf[SockDiag::LEN..]);

        let mut resp = InetDiagUdpResp {
            msg,
            ..Default::default()
        };

        for attr in attrs {
            match attr.header.rta_type as u8 {
                INET_DIAG_MEMINFO => resp.memory = bincode::deserialize(&attr.payload).unwrap(),
                _ => {}
            }
        }

        resp
    }
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug)]
pub struct SockDiagId {
    pub src_port: u16,
    pub dst_port: u16,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub interface: u32,
    pub cookie: [u32; 2],
}

impl Default for SockDiagId {
    fn default() -> Self {
        Self {
            src_port: 0,
            dst_port: 0,
            src_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            interface: 0,
            cookie: [0; 2],
        }
    }
}

impl SockDiagId {
    const LEN: usize = 48;
}

#[derive(Default, Debug)]
pub struct SockDiag {
    pub family: u8,
    pub state: u8,
    pub timer: u8,
    pub retrans: u8,
    pub id: SockDiagId,
    pub expires: u32,
    pub rqueue: u32,
    pub wqueue: u32,
    pub uid: u32,
    pub inode: u32,
}

struct ReadBuffer<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ReadBuffer<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read(&mut self) -> u8 {
        let c = self.buf[self.pos];
        self.pos += 1;
        c
    }

    fn read_n<const N: usize>(&mut self) -> [u8; N] {
        let s = &self.buf[self.pos..self.pos + N];
        self.pos += N;
        s.try_into().expect("failed to read array")
    }

    fn seek(&mut self, n: usize) {
        self.pos += n;
    }
}

impl SockDiag {
    const LEN: usize = SockDiagId::LEN + 24;

    pub fn deserialize(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::LEN {
            bail!("socket data short read: {}", buf.len())
        }

        let mut rb = ReadBuffer::new(buf);

        Ok(SockDiag {
            family: rb.read(),
            state: rb.read(),
            timer: rb.read(),
            retrans: rb.read(),
            id: SockDiagId {
                src_port: u16::from_be_bytes(rb.read_n::<2>()),
                dst_port: u16::from_be_bytes(rb.read_n::<2>()),
                src_ip: {
                    let ip = IpAddr::V4(Ipv4Addr::new(rb.read(), rb.read(), rb.read(), rb.read()));
                    rb.seek(12);
                    ip
                },
                dst_ip: {
                    let ip = IpAddr::V4(Ipv4Addr::new(rb.read(), rb.read(), rb.read(), rb.read()));
                    rb.seek(12);
                    ip
                },
                interface: u32::from_ne_bytes(rb.read_n::<4>()),
                cookie: [
                    u32::from_ne_bytes(rb.read_n::<4>()),
                    u32::from_ne_bytes(rb.read_n::<4>()),
                ],
            },
            expires: u32::from_ne_bytes(rb.read_n::<4>()),
            rqueue: u32::from_ne_bytes(rb.read_n::<4>()),
            wqueue: u32::from_ne_bytes(rb.read_n::<4>()),
            uid: u32::from_ne_bytes(rb.read_n::<4>()),
            inode: u32::from_ne_bytes(rb.read_n::<4>()),
        })
    }
}

#[derive(Deserialize, Default, Debug)]
pub struct TcpDiag {
    pub state: u8,
    pub ca_state: u8,
    pub retransmits: u8,
    pub probes: u8,
    pub backoff: u8,
    pub options: u8,
    // pub snd_wscale: u8,
    // pub rcv_wscale: u8,
    pub scales: u8,
    // pub delivery_rate_app_limited: u8,
    // pub fastopen_client_fail: u8,
    pub rate_limit_and_fast_open: u8,
    pub rto: u32,
    pub ato: u32,
    pub snd_mss: u32,
    pub rcv_mss: u32,
    pub unacked: u32,
    pub sacked: u32,
    pub lost: u32,
    pub retrans: u32,
    pub fackets: u32,
    pub last_data_send: u32,
    pub last_ack_sent: u32,
    pub last_data_recv: u32,
    pub last_ack_recv: u32,
    pub pmtu: u32,
    pub rcv_ssthresh: u32,
    pub rtt: u32,
    pub rttval: u32,
    pub snd_ssthresh: u32,
    pub snd_cwnd: u32,
    pub advmss: u32,
    pub reordering: u32,
    pub rcv_rtt: u32,
    pub rcv_space: u32,
    pub total_retrans: u32,
    pub pacing_rate: u64,
    pub max_pacing_rate: u64,
    pub bytes_acked: u64,
    pub bytes_received: u64,
    pub segs_out: u32,
    pub segs_in: u32,
    pub notsent_bytes: u32,
    pub min_rtt: u32,
    pub data_segs_in: u32,
    pub data_segs_out: u32,
    pub delivery_rate: u64,
    pub busy_time: u64,
    pub rwnd_limited: u64,
    pub sndbuf_limited: u64,
    pub delivered: u32,
    pub delivered_ce: u32,
    pub bytes_sent: u64,
    pub bytes_retrans: u64,
    pub dsack_dups: u32,
    pub reord_seen: u32,
    pub rcv_ooopack: u32,
    pub snd_wnd: u32,
}

#[derive(Deserialize, Default, Debug)]
pub struct TcpBbrDiag {
    pub bandwidth: u64,
    pub min_rtt: u32,
    pub pacing_gain: u32,
    pub cwnd_gain: u32,
}

#[derive(Deserialize, Default, Debug)]
pub struct Memory {
    rmem: u32,
    wmem: u32,
    fmem: u32,
    tmem: u32,
}
