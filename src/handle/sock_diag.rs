use std::ops::{Deref, DerefMut};

use anyhow::Result;

use crate::{
    core::message::Message,
    types::{
        message::Attribute,
        sock_diag::{InetDiagTcpResp, InetDiagUdpResp, SockDiagReq},
    },
};

use super::handle::SocketHandle;

const SOCK_DIAG_BY_FAMILY: u16 = 20;

pub enum DiagFamily {
    V4 = 2,
    V6 = 10,
}

pub struct SockDiagHandle<'a> {
    pub socket: &'a mut SocketHandle,
}

impl<'a> Deref for SockDiagHandle<'a> {
    type Target = SocketHandle;

    fn deref(&self) -> &Self::Target {
        self.socket
    }
}

impl DerefMut for SockDiagHandle<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.socket
    }
}

impl<'a> From<&'a mut SocketHandle> for SockDiagHandle<'a> {
    fn from(socket: &'a mut SocketHandle) -> Self {
        Self { socket }
    }
}

impl SockDiagHandle<'_> {
    pub fn tcp_info(&mut self, family: DiagFamily) -> Result<Vec<InetDiagTcpResp>> {
        let mut req = Message::new(SOCK_DIAG_BY_FAMILY, libc::NLM_F_DUMP);
        let msg = SockDiagReq::request_tcp_info(family as u8);

        req.add(&msg.serialize()?);

        let resp = self.request(&mut req, SOCK_DIAG_BY_FAMILY)?;

        Ok(resp
            .iter()
            .map(|b| InetDiagTcpResp::from(b.as_ref()))
            .collect())
    }

    pub fn udp_info(&mut self, family: DiagFamily) -> Result<Vec<InetDiagUdpResp>> {
        let mut req = Message::new(SOCK_DIAG_BY_FAMILY, libc::NLM_F_DUMP);
        let msg = SockDiagReq::request_udp_info(family as u8);

        req.add(&msg.serialize()?);

        let resp = self.request(&mut req, SOCK_DIAG_BY_FAMILY)?;

        Ok(resp
            .iter()
            .map(|b| InetDiagUdpResp::from(b.as_ref()))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use crate::handle::handle::SocketHandle;

    use super::DiagFamily;

    #[test]
    fn test_sock_diag_tcp_info() {
        let mut handle = SocketHandle::new(libc::NETLINK_INET_DIAG);
        let mut sock_diag_handle = handle.handle_sock_diag();

        let resp = sock_diag_handle.tcp_info(DiagFamily::V4).unwrap();

        assert!(!resp.is_empty());
        assert_eq!(resp[0].msg.family, DiagFamily::V4 as u8);
    }

    #[test]
    fn test_sock_diag_udp_info() {
        let mut handle = SocketHandle::new(libc::NETLINK_INET_DIAG);
        let mut sock_diag_handle = handle.handle_sock_diag();

        let resp = sock_diag_handle.udp_info(DiagFamily::V4).unwrap();

        assert!(!resp.is_empty());
        assert_eq!(resp[0].msg.family, DiagFamily::V4 as u8);
    }
}
