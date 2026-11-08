# Installation discipline review, 2026-09-22

This reviews `docs/architecture/agenxy-installation.md` against the native macOS
source installer, prebuilt lifecycle, launchd socket adapter and ADR-0017. The starting
commit is `1e2a3fc`. The actual checkout is `release/0.2.0`, three commits ahead of its
tracking branch; the supplied specification was untracked. The branch was not changed.

The installed product was inspected read-only. No install, update, recovery, uninstall,
owner-authentication prompt or privileged product repair was run.

## The installed generation

`Install/current` points to
`Generations/0.2.0-c690ee955306a2ba389672034cb3fcb257e07b9a67ad874e008b6d71e71ea8f4`.
Its public files are timestamped September 18 at 16:50, and the current link at 16:51.
Commit `7218c4d` is timestamped 17:05 that day. The installed CLI still emits the older
R701 missing-file diagnostic with the circular `remap system recover` hint.

The generation is not a lone executable. These five manifest-declared files exist and
their SHA-256 hashes match the installed manifest:

- `bin/remap`
- `libexec/remapd`
- `libexec/remap-install`
- `libexec/remap-resolver`
- `libexec/remap-system`

The manifest does **not** declare `libexec/remap-lifecycle`. This is the source payload
assembled by `tools/remap_native_package.py::_copy_inputs`. Its `NativeProductFiles`
contract omits that client; `tools/remap_macos_install.py::build_native_products` does
not stage it. Source lifecycle work uses the repository orchestrator and a verified,
temporarily published native helper. ADR-0017 explicitly records this limitation.

The prebuilt contract differs:
`MacOSPortableProduct.swift::MacOSPortableProductContract.requiredFiles` requires
`libexec/remap-lifecycle`; `MacOSPortableFileTree.swift::copyProduct` verifies that
product tree. An absent declared file is not a valid prebuilt generation.

`7218c4d` changed only the CLI explanation for a missing lifecycle executable. It did
not package the client or repair older installations. Its NotFound branch also called
the generic R701 constructor, retaining the circular recovery hint, and assumed that
absence proved source provenance. The new `Diagnostic::missing_lifecycle_client` names
the missing path and both possible cases, with an external remedy for each. It does not
infer provenance from absence alone.

Existing protections already verify source entries in `MacOSInstaller.validateSource`,
copy and hash each file in `FileSystemAuthority.copyRegularFile`, and classify the whole
stage in `InstallTransactionCoordinator.installOrUpdate`. This change additionally
puts full verification inside `GenerationStore.publish`, so a direct publication call
cannot publish a stage missing a declared component. This is defense at the publication
boundary, not evidence that the observed installation suffered a torn transaction.

The source distribution still cannot manage itself through `remap system`. Delivering
the prebuilt client's service and authorization contract in source installs remains an
explicit product gap. The owner must separately approve any installation change.

## Six failures

| Rule | Verdict | Code and evidence |
|---|---|---|
| 1. Guarded directory | **Conforms** by construction. | `MacOSInstallLayout.production` roots authority at `/`; `installerBase` fixes `/Library/Application Support/Agenxy/Remap/Install`; `MacOSGenerationImageStore.loadService` derives the program from the generation. `MacOSLaunchdPropertyList.validate` rejects a different program. `FileSystemAuthority.openDirectory` uses descriptor-relative `O_NOFOLLOW` traversal, so an owner-controlled symlink cannot redirect that root into Desktop. The checkout is build input, not the installed launchd program. The rejection now names the supplied path and expected generation path; the guarded-directory test covers Desktop, Documents, Downloads and iCloud Drive. |
| 2. Executable overwrite | **Fixed** at staging boundaries; installed generations already conformed. | `GenerationStore.stage` creates a new private stage. `FileSystemAuthority.createRegularFile` uses `O_EXCL`; `GenerationStore.publish` uses exclusive rename and refuses an existing generation. `PublicationStore.exchange` changes links or files by atomic exchange. An identical generation is verified or rejected, never rewritten. Python `stage_unsigned_executable`, `stage_package_file`, and Linux `_copy_source`/`_copy_asset` now use `xb` instead of overwrite-capable `shutil.copyfile`. `_finalize_signed_copy` publishes a fresh signed file by rename. The native bootstrap helper stores also publish exclusive staged files. |
| 3. Teardown race | **Fixed** for the lifecycle helper; daemon/resolver updates already did better than the original specification. | `MacOSInstallSystemEffectAdapter.waitForServiceToUnload` waits for absence and rejects changed program/plist identity, covered by `updateWaitsForLaunchdToFinishAnAsynchronousBootout`. `NativeMacOSLaunchdController.bootout` now provides that contract to every native caller, with bounded subprocesses and a bounded polling deadline. `PortableLifecycleService.bootout` delegates to `MacOSInstallerServiceLaunchd.bootoutIfLoaded`. Timeout and changed-identity tests prevent early return. Transaction failure still enters `InstallTransactionSteps.rollBackInstall`; failed rollback is recorded as recovery work, not success. |
| 4. Atomic, deterministic definitions | **Conforms** for the reviewed publication paths. | `PublicationStore.create` stages a sibling through `FileSystemAuthority.copyRegularFile`, which syncs bytes and metadata. `renameSwap`/`renameExclusive` sync the directory; displaced ownership is verified before removal, with restoration on failure. Source plist serialization uses `plistlib.dumps(..., sort_keys=True)`; `MacOSPortableSourceAssembler.writeLaunchd` serializes fixed typed dictionaries. The package determinism test checks complete manifest equality, and the new definition-publication test checks successful replacement, injected rename failure, preserved prior bytes, mode and no leftover temporary file. The all-renderer literal-fixture requirement remains open below. |
| 5. Packaged embedded assets | **Conforms** in source and gate wiring. | `remap-mcp/src/server.rs::MARK` embeds `../assets/remap-mark.svg` within its crate; privacy and fixture includes are also crate-local. `ui.rs` embeds generated `OUT_DIR/dashboard.html`, with its inputs under the crate. `tools/remap_tasks.py::task_check` calls `verify_packages`; `tools/remap_package.py::verify` packages the publishable dependency closure, extracts archives and checks them against extracted dependencies. Q009 now rejects escaping literal include paths, external symlink targets and unsupported dynamic paths; only confined generated OUT_DIR suffixes are admitted. Archive verification was not rerun in this restricted session. |
| 6. Older service, upgraded client | **Cannot yet, because** lifecycle version diagnostics are incomplete. | `remap-protocol/src/client.rs::validate_response` checks the returned protocol and correlation ID; `Diagnostic::protocol` tells the owner to update client and daemon together. `RemapControlClient.validate` does the same for the app. `RemapLifecycleRequest.validate` and `RemapLifecycleResponse.validate` reject unsupported schemas, but only name the schema category, and `RemapLifecycleCLIErrorDocument.data` can map that to a generic retry/recover hint. Typed payload decoding also precedes the schema check. A version-envelope check before version-dependent decoding, naming both versions and an external installer remedy, is still required. Compatible releases need not be rejected merely for different product version strings. |

The socket work in `crates/remapd/src/launchd.rs` is a separate platform boundary.
It adopts launchd's descriptors, refuses root daemon execution and checks declared
socket consistency. ADR-0017 correctly treats launchd's private bind address and root
listener credential as properties of socket activation. Those checks neither wait for
job teardown nor prove installed/running identity. No socket trust rule was changed.

## Positive duties

| Duty | Verdict and code |
|---|---|
| State installed and running identity; report both PIDs | **Cannot yet, because** `MacOSInstaller.status` and `MacOSInstallerServiceStatus` report generation, loaded plist/program and DNS state, but no manager PID or authenticated socket responder PID. `MacOSRuntimeHealthChecker.wait` and `MacOSResolverReadinessVerifier.wait` provide stronger acceptance than a loaded-job check, including effective DNS, but are not the required status comparison. The status schema needs an explicit, compatible extension. |
| Report persistent manager state | **Cannot yet, because** `LaunchctlCommand` has no `print-disabled` operation and status has no disabled-state field. Linux status also needs enablement/masking reporting; this product uses system units, so user lingering is not part of its current topology. A missing or failed job must not be labelled owner-disabled without evidence. |
| Never change persistent manager state implicitly | **Fixed** in macOS reconciliation: removed `launchd.enable` and the typed `enable` command. An owner-disabled service stays disabled; failed startup follows existing rollback/recovery. **Cannot yet claim this for Linux:** `remap-linux-system/src/system_publication.rs::unit_link_specs` publishes target-wants links as part of the install contract. Separate consent and preservation of an existing owner's enablement choice need review before claiming cross-platform conformity. |
| Name every displayed identity | **Conforms** on the reviewed macOS path: `MacOSLaunchdServiceKind.label`, `MacOSInstallerServiceLaunchd` and the source/portable plist renderers name each service, program and stdout/stderr destination. Both daemon streams deliberately use `/dev/null`; that is an explicit privacy policy, not an unnamed log file. **Cannot yet claim the Linux duty:** `remap-linux/src/systemd.rs` provides Remap unit descriptions but omits explicit `SyslogIdentifier`. |
| Refuse invalid daemon configuration at install time | **Conforms** for the admitted native image: `MacOSInstaller.preview` calls `validateSource`; `MacOSInstallConfiguration.validate`, `MacOSGenerationImageStore.loadService` and `MacOSLaunchdPropertyList.validate` enforce exact account, paths, arguments, upstream addresses, loopback sockets and resource policy. Runtime acceptance still verifies actual effects. Renderer-level control-character coverage remains incomplete below. |
| Minimize and bind privileged work | **Conforms** in the reviewed architecture: `tools/remap_macos_install.py` builds/signs/previews outside product mutation; `remap_macos_bootstrap.py::bootstrap_helper` verifies and stages the native authority. `RemapInstallUserPresence` implements ADR-0017's bounded invoking-user presence check. `InstallApprovalToken`, `MacOSInstallerApprovalVerifier` and `InstallTransactionCoordinator` revalidate the approved state under the native lock before effects. No new privileged interface was introduced. |

## Required tests and enforcement limits

- Test 1, guarded programs: added `guardedDirectoryProgramIsRefusedWithItsPathAndTheGenerationDestination`.
- Test 2, atomic definition/mode/cleanup: added
  `definitionReplacementIsAtomicAndLeavesTheCorrectModeWithoutTemporaryFiles`, including
  a failure before rename. This is filesystem transaction evidence, not a launchd E2E test.
- Test 3, every renderer against literal bytes: **cannot yet**. The source suite verifies
  deterministic whole packages and fields, and the generated-package compatibility test
  feeds Python output to Swift validation. Literal fixtures for every source, portable,
  installer-service and systemd renderer are not complete.
- Test 4, every renderer rejects controls and manager normalization: **cannot yet**.
  Exact privileged validation does not replace direct tests of every renderer. In
  particular, Python source renderers and the portable Swift renderer do not uniformly
  reject all control characters at their own input boundary.
- Test 5, parser depth: the existing
  `launchdObservationReadsTheServiceFieldsNotANestedSocketPath` verifies top-level fields;
  `NativeMacOSLaunchdController.field` also refuses duplicate values. Coverage for the
  missing persistent-state and PID parsers must accompany their implementation.
- Test 6, the three distinct status states: **cannot yet**. The current schema cannot
  express owner-disabled or a different process answering the socket.
- Test 7, all pure functions on both platforms: **cannot yet**. `.github/workflows/ci.yml`
  runs `make check` on xcode-27 and ubuntu-24.04; `task_test` runs Rust/Python on both, but
  Swift tests only on macOS. Pure Swift lifecycle parsing is coupled to Darwin/Security
  targets. Extract a portable test target before claiming Linux coverage for it. No
  Linux runner was available for this review.
- New shared tests 8 and 9: teardown delay/timeout/collision/absence tests, exclusive-copy
  regressions and missing-declared-component publication test were added.

`remap-quality` now adds Q009 and Q010. Q009 parses Rust include macros, including those
nested in other macros, and checks crate confinement after symlink resolution. Q010
rejects overwrite-capable `shutil.copyfile`, `copy2` and `copy` calls in installer and
bootstrap Python modules, literal Rust executable destinations passed to `fs::copy`,
`fs::write` or `File::create` (including `Path::new` and references), and `O_TRUNC` in the
native installation authority. Staging copies must enforce freshness themselves.

These are conservative source checks, not a general dataflow proof. Python aliases,
computed destinations, arbitrary wrappers and externally generated code require review
and tests. The Python primitive check and Swift truncation check are textual, so even a
comment containing the prohibited operation can be rejected. Native API behavior,
TCC consent, kernel signature caching, teardown timing, authenticated responder
identity, ownership drift, recovery and effective DNS are not established by static
checks. Cargo archive compilation and the OS matrix remain independent gate duties.

Quality caches now live under the ignored workspace `target` directory. This permits
the unchanged SwiftFormat and strict SwiftLint checks to run in a workspace sandbox.
No lint rule, warning policy, test or gate was suppressed. No dependency, entitlement,
wire format, unsafe block, shell script or standalone helper was added.

## Changes to the shared specification

The Remap copy now records practices that were stronger than the original text:
fixed-root confinement instead of a configurable guarded-path blacklist; immutable
verified generations; teardown identity checks; collision-safe atomic exchanges with
durability; building extracted Cargo archives; approval revalidation under lock; and
distribution-specific lifecycle capabilities with non-circular recovery guidance.
It also adds teardown and missing-component regression requirements.

**Compass and Supgang need this revised specification copied into their repositories.**
Only the Remap copy was changed here. ADR-0018 records the local platform-contract
changes and the outstanding privileged acceptance boundary.

## Changed files

Every path below is relative to the repository root. The specification was supplied as
an untracked file and remains untracked; no commit or branch switch was made.

| File | Change |
|---|---|
| `crates/remap-quality/src/main.rs` | Register installation policy and its tests. |
| `crates/remap-quality/src/model.rs` | Add Q009/Q010 diagnostics. |
| `crates/remap-quality/src/scan.rs` | Run installation checks for discovered sources. |
| `crates/remap-quality/src/installation_policy.rs` | Embedded-asset and executable-copy checks. |
| `crates/remap-quality/src/installation_policy_tests.rs` | Five policy regression tests. |
| `crates/remap/src/diagnostic.rs` | Missing-client diagnostic and regression test. |
| `crates/remap/src/runtime.rs` | Use that diagnostic for the macOS NotFound handoff. |
| `platforms/macos/Sources/RemapInstallKit/GenerationStore.swift` | Reverify a complete stage at publication. |
| `platforms/macos/Sources/RemapInstallKit/MacOSInstallSystemEffectAdapter.swift` | Remove implicit enablement; pass admitted identity into teardown. |
| `platforms/macos/Sources/RemapInstallKit/MacOSLaunchctl.swift` | Bounded, identity-checked bootout; remove enable command. |
| `platforms/macos/Sources/RemapInstallKit/MacOSLaunchdPropertyList.swift` | Name rejected program and correct destination. |
| `platforms/macos/Sources/RemapPortableInstaller/PortableLifecycleAuthority.swift` | Use shared lifecycle teardown. |
| `platforms/macos/Tests/RemapInstallKitTests/DefinitionPublicationTests.swift` | Atomic replacement and failure preservation. |
| `platforms/macos/Tests/RemapInstallKitTests/GenerationPublicationTests.swift` | Refuse a missing declared executable. |
| `platforms/macos/Tests/RemapInstallKitTests/GuardedProgramTests.swift` | Four guarded-directory cases. |
| `platforms/macos/Tests/RemapInstallKitTests/LaunchdTeardownTests.swift` | Five teardown cases, including replacement before mutation. |
| `platforms/macos/Tests/RemapInstallKitTests/MacOSInstallerFakes.swift` | Match the identity-bound bootout interface; remove fake enable. |
| `platforms/macos/Tests/RemapInstallKitTests/MacOSInstallerServiceLaunchdTests.swift` | Match the identity-bound bootout interface; remove fake enable. |
| `tests/python/test_macos_install.py` | Exclusive-copy collision, symlink and fresh-inode tests. |
| `tests/python/test_native_package.py` | Preserve an existing executable; assert source contract omits lifecycle client. |
| `tools/remap_linux_install.py` | Exclusive executable/asset staging. |
| `tools/remap_macos_install.py` | Shared exclusive unsigned staging used by signed copies. |
| `tools/remap_native_package.py` | Exclusive package-file staging. |
| `tools/remap_tasks.py` | Workspace-local lint caches. |
| `docs/architecture/ADR-0018-installation-discipline.md` | Decision and acceptance boundary. |
| `docs/architecture/agenxy-installation.md` | Shared discipline improvements. |
| `docs/engineering/installation-conformance.md` | This review, limitations and verification record. |

## Added test inventory

The five Rust policy tests are
`embedded_assets_must_stay_inside_the_published_crate`,
`embedded_asset_symlinks_cannot_escape_the_crate`,
`installer_copies_must_create_fresh_files_even_in_staging`,
`rust_literal_executable_writes_are_rejected`, and
`native_installer_authority_cannot_introduce_truncating_opens`.

The CLI test is
`missing_lifecycle_client_names_both_install_types_without_a_circular_remedy`.

The eight Swift test functions are
`definitionReplacementIsAtomicAndLeavesTheCorrectModeWithoutTemporaryFiles` (two cases),
`generationPublicationRefusesADeclaredExecutableMissingAfterStaging`,
`guardedDirectoryProgramIsRefusedWithItsPathAndTheGenerationDestination` (four cases),
`launchdBootoutWaitsForSIGTERMedToDisappearBeforeReturning`,
`launchdBootoutNamesTheJobWhenTeardownTimesOut`,
`launchdBootoutRefusesAReplacementJobDuringTeardown`,
`launchdBootoutRefusesAReplacedJobBeforeAnyMutation`, and
`launchdBootoutOfAnAbsentJobHasNoMutation`.

The three Python tests are
`test_executable_staging_refuses_an_existing_inode_and_symlink`,
`test_executable_staging_creates_a_fresh_inode`, and
`test_executable_package_copy_never_truncates_an_existing_destination`.
The existing deterministic-manifest test now also asserts that a source manifest does
not declare the prebuilt lifecycle client.

## Verification

The owner identified a pre-existing freshness blocker: `make check` requires installed
mise to match the latest GitHub release, and the upgrade is rate-limited. `make check`
was not run and no freshness check was weakened. The requested component commands were
run with `UV_CACHE_DIR=/private/tmp/remap-uv-cache`, since the default user cache is not
writable in this workspace sandbox.

| Command or check | Result |
|---|---|
| `uv run python -m tools.remap_tasks quality` | Passed: Ruff, formatting, strict Python typing, SwiftFormat, strict SwiftLint and `remap-quality`. Workspace-local lint caches avoid writes to protected user caches. |
| `uv run python -m tools.remap_tasks test` | Failed at the Rust suite: 27 CLI tests passed, three failed where the sandbox denies local socket operations. The failures are `human_commands_share_the_authoritative_revision`, `humans_can_preview_and_apply_the_same_atomic_document`, and `hostile_local_listeners_cannot_extend_the_overall_probe_deadline`. The task stops there, so its later stages did not run. |
| `cargo test --locked -p remap-quality` | 17 passed, including all five new policy tests. |
| `cargo test --locked -p remap --bin remap missing_lifecycle_client` | The new diagnostic regression passed. |
| `cargo clippy --locked -p remap-quality -p remap --all-targets --all-features -- -D warnings` | Passed. After the final asset-path refinement, the quality crate's all-target Clippy check passed again. |
| `swift test ... --filter RemapInstallKitTests` | All 145 passed on the final source, including the five teardown regressions, missing-component rejection, guarded paths and both atomic-definition cases. |
| `swift test ... --filter RemapPortableInstallerTests` | 25 of 27 passed. Unchanged `commandRunnerCapturesBoundedAppleToolOutput` failed Apple-signature validation for the system tool; `commandRunnerKillsDescendantsThatKeepOutputOpen` could not read its child PID fixture. These failures remain unresolved in this execution environment. |
| `uv run python -m unittest discover -s tests/python -v` | 192 run: 187 passed, two skipped, three errors. The unchanged session/group bootstrap test produced an empty process report; the generated-signature-copy and extended-attribute tests could not perform their launchd operations. No product lifecycle command was invoked to work around them. |
| `uv run python -m unittest tests.python.test_macos_install tests.python.test_native_package tests.python.test_linux_install tests.python.test_tasks -v` | All 72 passed on the final Python changes. |
| `cargo fmt --all --check`, `git diff --check` | Passed. |
| Installed manifest inspection | Read-only `remap system status`, directory/link inspection, and SHA-256 verification of the five declared executables. Confirmed the absent client is not declared by this source generation. |

Cargo commands used `mise exec --`. Swift commands used `xcrun swift test
--package-path platforms/macos`, with module, configuration, security and manifest
caches placed in writable temporary directories. The first Swift attempt was refused
by nested `sandbox-exec`; the successful run used SwiftPM's `--disable-sandbox` while
remaining inside the session's filesystem and network sandbox. This changes build-tool
subprocess isolation, not product security checks or test assertions.

Browser tests, actual extracted-crate packaging, a Linux host, independent adversarial
review and privileged installation/update/rollback acceptance were not completed in
this session. Full `make check` and full `test` are not claimed green. The installed
generation remains unchanged and still requires an owner-approved lifecycle decision.
