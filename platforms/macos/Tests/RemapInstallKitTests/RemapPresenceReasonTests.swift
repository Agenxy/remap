// SPDX-License-Identifier: GPL-3.0-or-later
import RemapInstallKit
import Testing

/// macOS renders the reason as "<program> is trying to <reason>.", so a capital
/// letter or a full stop of its own reads wrongly in the dialog.
@Test
func presenceReasonCompletesTheSystemSentence() {
    let reason = RemapPresenceReason.reviewedChanges
    #expect(reason.first?.isLowercase == true)
    #expect(!reason.hasSuffix("."))
    #expect(reason.contains("Remap"))
}
