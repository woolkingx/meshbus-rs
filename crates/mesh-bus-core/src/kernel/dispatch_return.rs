use super::dispatch::DispatchRuntime;
use crate::{Frame, PacketId, ReturnEvent, ReturnSemantics};

pub(super) async fn send_return(
    return_tx: &tokio::sync::mpsc::Sender<ReturnEvent>,
    runtime: &DispatchRuntime,
    frame: &Frame,
    event: ReturnEvent,
) -> bool {
    send_return_with_packet_id(return_tx, runtime, frame, event, frame.packet_id).await
}

pub(super) async fn send_return_with_packet_id(
    return_tx: &tokio::sync::mpsc::Sender<ReturnEvent>,
    runtime: &DispatchRuntime,
    frame: &Frame,
    event: ReturnEvent,
    packet_id: PacketId,
) -> bool {
    if frame.return_semantics == ReturnSemantics::Direct {
        return return_tx.send(event).await.is_ok();
    }
    let inserted = runtime
        .packet_returns
        .lock()
        .await
        .insert((frame.flow_id.clone(), packet_id));
    if inserted {
        return return_tx.send(event).await.is_ok();
    }
    true
}
