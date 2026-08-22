import RemapControlKit

struct AppDiagnosticContent: Equatable {
    let code: String
    let message: String
    let hint: String?

    init(_ diagnostic: RemapDiagnostic) {
        code = diagnostic.code
        switch diagnostic.code {
        case "E_SNAPSHOT_CHANGED":
            message = AppText.localized("The registry changed while the app refreshed.")
            hint = AppText.localized("Wait a moment, then refresh again.")
        case "E_CONTROL_PROTOCOL":
            message = AppText.localized("The Remap app and background service aren't communicating correctly.")
            hint = AppText.localized("Update the Remap app and service together, then retry.")
        case "E_DAEMON_UNAVAILABLE":
            message = AppText.localized("Remap isn't running in the background.")
            hint = AppText.localized("Reinstall Remap, then refresh. Your saved mappings are unchanged.")
        case "E_NATIVE_APP":
            message = AppText.localized("The app could not complete the operation.")
            hint = AppText.localized("Refresh the app. If the problem remains, run remap doctor.")
        default:
            message = diagnostic.message
            hint = diagnostic.hint
        }
    }
}

func appDiagnostic(_ error: any Error) -> RemapDiagnostic {
    if let diagnostic = error as? RemapDiagnostic {
        return diagnostic
    }
    return RemapDiagnostic(
        code: "E_NATIVE_APP",
        message: AppText.localized("The app could not complete the operation."),
        hint: AppText.localized("Refresh the app. If the problem remains, run remap doctor."),
        retryable: true
    )
}
