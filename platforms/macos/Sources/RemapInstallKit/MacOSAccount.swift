import Darwin
import Foundation

struct MacOSAccount: Equatable, Sendable {
    let userName: String
    let groupName: String
    let homeDirectory: InstallAbsolutePath
}

private struct MacOSUserRecord {
    let name: String
    let groupID: gid_t
    let homeDirectory: String
}

enum MacOSAccountLookup {
    static func account(for ownerUID: UInt32) throws -> MacOSAccount {
        let user = try userRecord(for: uid_t(ownerUID))
        let groupName = try groupRecord(for: user.groupID)
        guard user.name != "root" else {
            throw InstallError.invalidManifest("the native daemon account must not be root")
        }
        return try MacOSAccount(
            userName: user.name,
            groupName: groupName,
            homeDirectory: InstallAbsolutePath(user.homeDirectory)
        )
    }

    private static func userRecord(for userID: uid_t) throws -> MacOSUserRecord {
        var record = passwd()
        var result: UnsafeMutablePointer<passwd>?
        var buffer = [CChar](repeating: 0, count: 16384)
        let status = getpwuid_r(userID, &record, &buffer, buffer.count, &result)
        guard status == 0, result != nil,
              let name = record.pw_name,
              let directory = record.pw_dir
        else {
            throw InstallError.operatingSystem("resolve native daemon account", status == 0 ? ENOENT : status)
        }
        return MacOSUserRecord(
            name: String(cString: name),
            groupID: record.pw_gid,
            homeDirectory: String(cString: directory)
        )
    }

    private static func groupRecord(for groupID: gid_t) throws -> String {
        var record = group()
        var result: UnsafeMutablePointer<group>?
        var buffer = [CChar](repeating: 0, count: 16384)
        let status = getgrgid_r(groupID, &record, &buffer, buffer.count, &result)
        guard status == 0, result != nil, let name = record.gr_name else {
            throw InstallError.operatingSystem("resolve native daemon group", status == 0 ? ENOENT : status)
        }
        return String(cString: name)
    }
}
