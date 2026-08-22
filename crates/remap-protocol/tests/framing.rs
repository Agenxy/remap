//! Executable specifications for the bounded local-control frame.

use remap_protocol::{
    CONTROL_PROTOCOL_VERSION, Command, ControlRequest, MAX_CONTROL_FRAME_BYTES, Surface,
    read_frame, write_frame,
};

#[tokio::test]
async fn frame_round_trip_preserves_request() -> Result<(), Box<dyn std::error::Error>> {
    let request = ControlRequest {
        protocol: CONTROL_PROTOCOL_VERSION.to_owned(),
        request_id: "probe-1".to_owned(),
        surface: Surface::Probe,
        client_version: "0.1.0".to_owned(),
        command: Command::Status,
    };
    let (mut writer, mut reader) = tokio::io::duplex(4096);
    let sent = request.clone();
    let (write, received) = tokio::join!(
        write_frame(&mut writer, &sent),
        read_frame::<ControlRequest, _>(&mut reader),
    );
    write?;
    let received = received?;
    assert_eq!(received, request);
    Ok(())
}

#[tokio::test]
async fn oversized_declared_frame_is_rejected_before_payload_allocation() {
    let oversized = u32::try_from(MAX_CONTROL_FRAME_BYTES + 1).unwrap_or(u32::MAX);
    let bytes = oversized.to_be_bytes();
    let mut input = bytes.as_slice();
    let result = read_frame::<ControlRequest, _>(&mut input).await;
    let Err(error) = result else {
        assert!(result.is_err(), "oversized frame must fail");
        return;
    };
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}
