use super::registry::Registry;
use super::runtime::{Bus, build};
use super::types::BusError;
use crate::{DatagramEgress, ObserverPlugin, SchedulerPlugin, StreamEgress};
use mb_health::HealthPolicy;

pub struct BusBuilder {
    reg: Registry,
}

impl BusBuilder {
    pub fn new() -> Self {
        Self {
            reg: Registry::new(),
        }
    }

    pub fn scheduler(mut self, s: Box<dyn SchedulerPlugin>) -> Self {
        self.reg.set_scheduler(s);
        self
    }

    pub fn add_stream_egress(mut self, e: Box<dyn StreamEgress>) -> Self {
        self.reg.add_stream_egress(e);
        self
    }

    pub fn add_datagram_egress(mut self, e: Box<dyn DatagramEgress>) -> Self {
        self.reg.add_datagram_egress(e);
        self
    }

    /// Direct EgressPlugin backdoor — part of the published owner-test data contract (0.4.39).
    /// Runtime application participants must use `add_stream_egress`/`add_datagram_egress` instead.
    pub fn add_egress(mut self, e: Box<dyn crate::EgressPlugin>) -> Self {
        self.reg.add_egress(e);
        self
    }

    pub fn add_observer(mut self, o: Box<dyn ObserverPlugin>) -> Self {
        self.reg.add_observer(o);
        self
    }

    pub fn health_policy(mut self, policy: HealthPolicy) -> Self {
        self.reg.set_health_policy(policy);
        self
    }

    pub async fn build(self) -> Bus {
        build(self.reg).expect("invalid bus config")
    }

    pub async fn try_build(self) -> Result<Bus, BusError> {
        build(self.reg)
    }
}

impl Default for BusBuilder {
    fn default() -> Self {
        Self::new()
    }
}
