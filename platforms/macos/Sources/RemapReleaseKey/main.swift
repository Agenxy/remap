// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation

do {
    try ReleaseKeyTool.run(ReleaseKeyCommand.parse(Array(CommandLine.arguments.dropFirst())))
} catch {
    let message = "remap-release-key: \(error.localizedDescription)\n"
    try? FileHandle.standardError.write(contentsOf: Data(message.utf8))
    exit(2)
}
