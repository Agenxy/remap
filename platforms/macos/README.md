# macOS platform

This directory will contain the Swift app, Network Extension entry point,
Service Management integration, Apple security adapters, entitlements, Xcode
project, and packaging configuration introduced at M3.

No entitlement file is committed during M0. Bundle identifiers, Team ID,
provisioning profiles, App Groups, Keychain access groups, and daemon hosting
must be established by the signed prototype rather than guessed in advance.

Daily work remains shell-first with `xcodebuild`; the Xcode IDE is optional.

