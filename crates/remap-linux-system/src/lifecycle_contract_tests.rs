use crate::install_model::{
    DirectoryProvenance, Generation, InstallPhase, PublicDirectory, RollbackStep, UninstallStep,
};
use crate::lifecycle_observation::os_release_value;

use super::{
    LinkCandidate, Operation, accepted_generation, classify_status_observation,
    directory_publication_effects, hex, link_selection_hint, plan_token, publication_effects,
    require_token, require_update_capability, sort_publications,
};

#[test]
fn status_reports_only_health_accepted_generations_as_active() {
    let mut record = crate::install_model::tests::sample_record();
    for phase in [InstallPhase::Active, InstallPhase::Pruning] {
        record.phase = phase;
        assert_eq!(
            accepted_generation(Some(&record), true),
            Some(&record.current)
        );
        assert_eq!(accepted_generation(Some(&record), false), None);
    }
    for phase in [
        InstallPhase::Staging,
        InstallPhase::Staged,
        InstallPhase::Published,
        InstallPhase::RollingBack(RollbackStep::StartPrevious),
        InstallPhase::RollingBack(RollbackStep::Finalize),
        InstallPhase::Uninstalling(UninstallStep::Finalize),
    ] {
        record.phase = phase;
        assert_eq!(accepted_generation(Some(&record), true), None);
    }
    assert_eq!(accepted_generation(None, true), None);
}

#[test]
fn link_guidance_matches_supported_primary_cardinality() {
    let candidate = |index, selection_state: &str| LinkCandidate {
        link_index: index,
        interface_name: format!("eth{index}"),
        backend: "systemd_networkd".to_owned(),
        selection_state: selection_state.to_owned(),
    };
    let secondary = candidate(1, "supported_secondary");
    let primary = candidate(2, "supported_primary");
    assert_eq!(
        link_selection_hint(false, false, std::slice::from_ref(&secondary)),
        Some(
            "no supported primary interface is available; inspect link candidates and resolver ownership"
        )
    );
    assert_eq!(
        link_selection_hint(false, false, std::slice::from_ref(&primary)),
        Some("the only supported primary interface will be selected automatically")
    );
    assert_eq!(
        link_selection_hint(
            false,
            false,
            &[primary.clone(), candidate(3, "supported_primary")]
        ),
        Some("select one supported primary interface with REMAP_LINUX_LINK=<index> make install")
    );
    assert_eq!(
        link_selection_hint(true, false, std::slice::from_ref(&primary)),
        None
    );
    assert_eq!(link_selection_hint(false, true, &[primary]), None);
}

#[test]
fn status_uses_one_active_integrity_observation() {
    let invalid = classify_status_observation(true, false, false);
    assert!(invalid.0);
    assert_eq!(
        invalid.1,
        Some("run make recover to inspect the exact blocked integrity invariant without mutation")
    );

    let valid = classify_status_observation(false, false, false);
    assert_eq!(valid, (false, None));

    let recoverable = classify_status_observation(false, true, false);
    assert!(recoverable.0);
    assert_eq!(
        recoverable.1,
        Some("run make recover to preview and approve exact recovery effects")
    );
}

#[test]
fn update_requires_the_current_resolver_rebase_capability() {
    let mut record = crate::install_model::tests::sample_record();
    assert!(require_update_capability(Operation::Update, Some(&record)).is_ok());
    record.current.resolver_rebase_capability = 2;
    assert_eq!(
        require_update_capability(Operation::Update, Some(&record))
            .err()
            .map(|value| value.kind()),
        Some(std::io::ErrorKind::Unsupported)
    );
    record.current.resolver_rebase_capability = 1;
    let error = require_update_capability(Operation::Update, Some(&record));
    assert_eq!(
        error.err().map(|value| value.kind()),
        Some(std::io::ErrorKind::Unsupported)
    );
    assert!(require_update_capability(Operation::Uninstall, Some(&record)).is_ok());
}

#[test]
fn approval_tokens_are_canonical_and_strict() -> std::io::Result<()> {
    let token = hex(&[0xab; 32]);
    assert_eq!(token, "ab".repeat(32));
    require_token(&token, &token)?;
    assert!(require_token(&token, &token.to_uppercase()).is_err());
    assert!(require_token(&token, &token[..63]).is_err());
    Ok(())
}

#[test]
fn os_release_parser_accepts_only_exact_keys() {
    let text = "ID=ubuntu\nVERSION_ID=\"24.04\"\nBUILD_ID=x\n";
    assert_eq!(os_release_value(text, "ID").as_deref(), Some("ubuntu"));
    assert_eq!(
        os_release_value(text, "VERSION_ID").as_deref(),
        Some("24.04")
    );
    assert_eq!(os_release_value(text, "VERSION"), None);
}

#[test]
fn approval_token_binds_state_generation_effects_and_publications() -> std::io::Result<()> {
    let publications = publication_effects(Operation::Update, Some("old"), Some("new"));
    assert!(publications.iter().all(|effect| {
        effect.action == "repoint"
            && effect.previous_generation_id.as_deref() == Some("old")
            && effect.next_generation_id.as_deref() == Some("new")
    }));
    let effects = vec!["replace one generation".to_owned()];
    let generation = crate::install_model::tests::generation(3);
    let record = crate::install_model::tests::sample_record();
    let install_effects = crate::lifecycle_effects::install(
        Operation::Install,
        &generation,
        None,
        publications.len(),
    );
    let update_effects = crate::lifecycle_effects::install(
        Operation::Update,
        &generation,
        Some(&record),
        publications.len(),
    );
    assert_ne!(install_effects, update_effects);
    let base = plan_token(
        Operation::Update,
        Some([1; 32]),
        Some([5; 32]),
        [2; 32],
        &effects,
        &publications,
    )?;
    let changed_state = plan_token(
        Operation::Update,
        Some([1; 32]),
        Some([5; 32]),
        [3; 32],
        &effects,
        &publications,
    )?;
    let changed_generation = plan_token(
        Operation::Update,
        Some([4; 32]),
        Some([5; 32]),
        [2; 32],
        &effects,
        &publications,
    )?;
    let changed_source = plan_token(
        Operation::Update,
        Some([1; 32]),
        Some([6; 32]),
        [2; 32],
        &effects,
        &publications,
    )?;
    let changed_runtime_effect = plan_token(
        Operation::Update,
        Some([1; 32]),
        Some([5; 32]),
        [2; 32],
        &update_effects,
        &publications,
    )?;
    assert_ne!(base, changed_state);
    assert_ne!(base, changed_generation);
    assert_ne!(base, changed_source);
    assert_ne!(base, changed_runtime_effect);
    Ok(())
}

#[test]
fn created_public_directories_are_exact_typed_publications() -> std::io::Result<()> {
    let generation_id = uuid::Uuid::from_u128(1);
    let generation = Generation {
        id: generation_id,
        manifest_digest: [0; 32],
        product_version: "0.1.1".to_owned(),
        account: "person".to_owned(),
        group: "people".to_owned(),
        owner_uid: 1000,
        daemon_uid: 1001,
        link: 2,
        interface_name: Some("eth0".to_owned()),
        resolver_manager: Some(remap_linux::ResolverLinkManager::SystemdNetworkd),
        resolver_rebase_capability: crate::install_model::RESOLVER_REBASE_CAPABILITY,
        artifacts: Vec::new(),
        public_directories: vec![
            PublicDirectory {
                path: "/usr/share/zsh/site-functions".to_owned(),
                provenance: DirectoryProvenance::CreatedByRemap,
                identity: None,
            },
            PublicDirectory {
                path: "/usr/share/fish".to_owned(),
                provenance: DirectoryProvenance::CreatedByRemap,
                identity: None,
            },
            PublicDirectory {
                path: "/usr/share/zsh".to_owned(),
                provenance: DirectoryProvenance::Preexisting,
                identity: None,
            },
        ],
    };
    let id = generation_id.to_string();
    let mut effects = directory_publication_effects(&generation, "create", None, Some(&id))?;
    sort_publications(&mut effects);

    assert_eq!(effects.len(), 2);
    assert_eq!(effects[0].action, "create");
    assert_eq!(effects[0].path, "/usr/share/fish");
    assert_eq!(effects[0].previous_generation_id, None);
    assert_eq!(effects[0].next_generation_id.as_deref(), Some(id.as_str()));
    assert_eq!(effects[1].path, "/usr/share/zsh/site-functions");
    Ok(())
}
