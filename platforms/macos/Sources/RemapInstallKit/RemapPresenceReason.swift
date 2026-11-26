// SPDX-License-Identifier: GPL-3.0-or-later

/// What a lifecycle change tells macOS it wants the owner's presence for.
///
/// macOS completes the sentence itself, as "<program> is trying to <reason>.",
/// so the reason is a lowercase verb phrase with no closing full stop. Every
/// program that asks for the same approval asks in the same words.
public enum RemapPresenceReason {
    public static let reviewedChanges = "apply the Remap changes you just reviewed"
}
