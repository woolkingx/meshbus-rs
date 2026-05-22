#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum CoreEventId {
    FlowOpened,
    FlowPathChanged,
    FlowClosed,
    PathIoError,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct ObsEventId(pub u32);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum EventTypeId {
    Core(CoreEventId),
    Obs(ObsEventId),
}

pub const CORE_RANGE_END: u32 = 16;
pub const OBS_MESHSEC_DROP: EventTypeId = EventTypeId::Obs(ObsEventId(0));
pub const OBS_NATIVE_DROP: EventTypeId = EventTypeId::Obs(ObsEventId(1));

impl EventTypeId {
    pub fn as_u32(self) -> u32 {
        match self {
            EventTypeId::Core(CoreEventId::FlowOpened) => 0,
            EventTypeId::Core(CoreEventId::FlowPathChanged) => 1,
            EventTypeId::Core(CoreEventId::FlowClosed) => 2,
            EventTypeId::Core(CoreEventId::PathIoError) => 3,
            EventTypeId::Obs(ObsEventId(n)) => CORE_RANGE_END + n,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DeliveryPolicy {
    Lossy,
    Reliable,
}

#[derive(Clone, Debug)]
pub struct EventTypeSpec {
    pub id: EventTypeId,
    pub schema_hash: u64,
    pub multi_writer: bool,
    pub delivery: DeliveryPolicy,
}

pub fn default_event_type_specs() -> Vec<EventTypeSpec> {
    vec![
        EventTypeSpec {
            id: EventTypeId::Core(CoreEventId::FlowOpened),
            schema_hash: 0xC001_0001,
            multi_writer: false,
            delivery: DeliveryPolicy::Reliable,
        },
        EventTypeSpec {
            id: EventTypeId::Core(CoreEventId::FlowPathChanged),
            schema_hash: 0xC001_0002,
            multi_writer: false,
            delivery: DeliveryPolicy::Reliable,
        },
        EventTypeSpec {
            id: EventTypeId::Core(CoreEventId::FlowClosed),
            schema_hash: 0xC001_0003,
            multi_writer: false,
            delivery: DeliveryPolicy::Reliable,
        },
        EventTypeSpec {
            id: EventTypeId::Core(CoreEventId::PathIoError),
            schema_hash: 0xC001_0004,
            multi_writer: false,
            delivery: DeliveryPolicy::Lossy,
        },
        EventTypeSpec {
            id: OBS_MESHSEC_DROP,
            schema_hash: 0x0B5E_C001,
            multi_writer: true,
            delivery: DeliveryPolicy::Lossy,
        },
        EventTypeSpec {
            id: OBS_NATIVE_DROP,
            schema_hash: 0x0B5E_C002,
            multi_writer: true,
            delivery: DeliveryPolicy::Lossy,
        },
    ]
}
