//! Local service-sink egress for native direct reverse stream.
//!
//! A source selects a service through the normal scheduler; the data plane
//! opens a local connector to the configured endpoint. `request.target` is
//! service-intent metadata only and never used for the dial. TCP session
//! machinery is delegated to a fixed-target [`TcpEgress`] so no session,
//! split, or splice code is duplicated.

use async_trait::async_trait;
use mb_endpoint::Endpoint;
use mb_socket_tune::SocketBufferConfig;
use mesh_bus_core::{
    BusSessionInfo, BusSessionRequest, Capabilities, DatagramEgress, DatagramSession,
    DisconnectReason, ExitId, StreamEgress, StreamSession,
};
use mesh_bus_egress_tcp::TcpEgress;
use mesh_bus_egress_udp::UdpEgress;
use std::time::Duration;

pub struct ServiceTcpEgress {
    service_id: String,
    inner: TcpEgress,
}

impl ServiceTcpEgress {
    pub fn new(id: ExitId, service_id: String, connect: Endpoint, timeout: Duration) -> Self {
        Self {
            service_id,
            inner: TcpEgress::new(id, timeout).with_fixed_target(connect),
        }
    }

    /// Tag this service sink with route_group labels. A session whose
    /// `BusSessionRequest.route_group` is `Some(g)` reaches this sink only if
    /// `g` appears in `groups`.
    pub fn with_groups(mut self, groups: Vec<String>) -> Self {
        self.inner = self.inner.with_groups(groups);
        self
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }
}

#[async_trait]
impl StreamEgress for ServiceTcpEgress {
    fn id(&self) -> &ExitId {
        self.inner.id()
    }

    fn capabilities(&self) -> &Capabilities {
        self.inner.capabilities()
    }

    async fn open_stream(
        &self,
        request: &BusSessionRequest,
        info: BusSessionInfo,
    ) -> Result<Box<dyn StreamSession>, DisconnectReason> {
        self.inner.open_stream(request, info).await
    }
}

pub struct ServiceUdpEgress {
    service_id: String,
    inner: UdpEgress,
}

impl ServiceUdpEgress {
    pub fn new(id: ExitId, service_id: String, connect: Endpoint, timeout: Duration) -> Self {
        Self {
            service_id,
            inner: UdpEgress::new(id, timeout).with_fixed_target(connect),
        }
    }

    /// Tag this service sink with route_group labels. A datagram session whose
    /// `BusSessionRequest.route_group` is `Some(g)` reaches this sink only if
    /// `g` appears in `groups`.
    pub fn with_groups(mut self, groups: Vec<String>) -> Self {
        self.inner = self.inner.with_groups(groups);
        self
    }

    pub fn with_socket_buffers(mut self, config: SocketBufferConfig) -> Self {
        self.inner = self.inner.with_socket_buffers(config);
        self
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }
}

#[async_trait]
impl DatagramEgress for ServiceUdpEgress {
    fn id(&self) -> &ExitId {
        self.inner.id()
    }

    fn capabilities(&self) -> &Capabilities {
        self.inner.capabilities()
    }

    fn max_payload_bytes(&self) -> usize {
        self.inner.max_payload_bytes()
    }

    async fn open_datagram(
        &self,
        request: &BusSessionRequest,
        info: BusSessionInfo,
    ) -> Result<Box<dyn DatagramSession>, DisconnectReason> {
        self.inner.open_datagram(request, info).await
    }
}
