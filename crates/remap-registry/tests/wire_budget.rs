//! Worst-case executable proof that valid results fit the control wire.

use remap_protocol::{
    Change, Command, CommandResult, ControlResponse, HostPolicy, MAX_ATOMIC_CHANGE_COUNT,
    MAX_CONTROL_FRAME_BYTES, MAX_MAPPING_PAGE_SIZE, MAX_TARGET_BYTES, Surface,
};
use remap_registry::Registry;

const CREATE_ONE: &str = "4fd7ddf4-e7e3-4cb6-a68a-1873bb705783";
const CREATE_TWO: &str = "f34cc920-e6a0-4b22-aa38-c8c14e0426da";
const UPDATE: &str = "308a25a4-950a-4639-bb45-b40cc0f158fd";

#[test]
fn maximum_pages_and_update_receipts_fit_one_control_frame()
-> Result<(), Box<dyn std::error::Error>> {
    let mut registry = Registry::open_in_memory()?;
    let first = changes(0, MAX_ATOMIC_CHANGE_COUNT, 'a');
    apply(&mut registry, 0, CREATE_ONE, first)?;
    let second = changes(
        MAX_ATOMIC_CHANGE_COUNT,
        usize::from(MAX_MAPPING_PAGE_SIZE),
        'a',
    );
    apply(&mut registry, 1, CREATE_TWO, second)?;

    let listed = registry.execute(
        Command::List {
            after: None,
            limit: MAX_MAPPING_PAGE_SIZE,
            include_disabled: true,
        },
        Surface::Probe,
    )?;
    assert_control_frame_fits(&listed)?;
    let CommandResult::List(page) = listed else {
        return Err("list returned the wrong result kind".into());
    };
    assert_eq!(page.mappings.len(), usize::from(MAX_MAPPING_PAGE_SIZE));

    let update = changes(0, MAX_ATOMIC_CHANGE_COUNT, 'b');
    let receipt = apply(&mut registry, 2, UPDATE, update.clone())?;
    assert_control_frame_fits(&receipt)?;
    let retry = apply(&mut registry, 2, UPDATE, update)?;
    assert_eq!(retry, receipt);
    Ok(())
}

fn changes(start: usize, end: usize, fill: char) -> Vec<Change> {
    (start..end)
        .map(|index| Change::Set {
            pattern: format!("name-{index:03}.example"),
            target: maximum_target(fill),
            host_policy: HostPolicy::PreserveClient,
            enabled: None,
        })
        .collect()
}

fn maximum_target(fill: char) -> String {
    const PREFIX: &str = "https://example.com/";
    format!(
        "{PREFIX}{}",
        fill.to_string().repeat(MAX_TARGET_BYTES - PREFIX.len())
    )
}

fn apply(
    registry: &mut Registry,
    revision: u64,
    operation_id: &str,
    changes: Vec<Change>,
) -> Result<CommandResult, remap_protocol::Diagnostic> {
    registry.execute(
        Command::Apply {
            expected_revision: revision,
            operation_id: operation_id.to_owned(),
            changes,
        },
        Surface::Mcp,
    )
}

fn assert_control_frame_fits(result: &CommandResult) -> Result<(), serde_json::Error> {
    let response = ControlResponse::success("f".repeat(128), result.clone());
    let encoded = serde_json::to_vec(&response)?;
    assert!(encoded.len() <= MAX_CONTROL_FRAME_BYTES);
    Ok(())
}
