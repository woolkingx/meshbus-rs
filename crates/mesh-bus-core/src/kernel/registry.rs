use crate::{
    DatagramEgress, EgressPlugin, ObserverPlugin, SchedulerPlugin, StreamEgress,
    egress_adapter::{DatagramEgressAdapter, StreamEgressAdapter},
};
use mb_health::HealthPolicy;

pub struct Registry {
    pub(crate) egresses: Vec<Box<dyn EgressPlugin>>,
    pub(crate) observers: Vec<Box<dyn ObserverPlugin>>,
    pub(crate) scheduler: Option<Box<dyn SchedulerPlugin>>,
    pub(crate) health_policy: HealthPolicy,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            egresses: vec![],
            observers: vec![],
            scheduler: None,
            health_policy: HealthPolicy::default(),
        }
    }

    pub fn add_stream_egress(&mut self, e: Box<dyn StreamEgress>) {
        self.egresses.push(Box::new(StreamEgressAdapter::new(e)));
    }

    pub fn add_datagram_egress(&mut self, e: Box<dyn DatagramEgress>) {
        self.egresses.push(Box::new(DatagramEgressAdapter::new(e)));
    }

    /// Direct EgressPlugin insertion — part of the published owner-test data contract (0.4.39).
    pub fn add_egress(&mut self, e: Box<dyn EgressPlugin>) {
        self.egresses.push(e);
    }

    pub fn add_observer(&mut self, o: Box<dyn ObserverPlugin>) {
        self.observers.push(o);
    }

    pub fn set_scheduler(&mut self, s: Box<dyn SchedulerPlugin>) {
        self.scheduler = Some(s);
    }

    pub fn set_health_policy(&mut self, policy: HealthPolicy) {
        self.health_policy = policy;
    }

    pub fn egress_count(&self) -> usize {
        self.egresses.len()
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}
