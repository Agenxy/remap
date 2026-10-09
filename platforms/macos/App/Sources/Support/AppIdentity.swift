// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

enum AppIdentity {
    static var version: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
            ?? "development"
    }
}
