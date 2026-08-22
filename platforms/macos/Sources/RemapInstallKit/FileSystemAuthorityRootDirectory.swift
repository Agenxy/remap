import Darwin

public extension FileSystemAuthority {
    /// Lists the already-open authority root without reopening its pathname.
    func listRootDirectory() throws -> [String] {
        let descriptor = dup(root.rawValue)
        guard descriptor >= 0 else {
            throw InstallError.operatingSystem("duplicate installer authority root", errno)
        }
        guard let stream = fdopendir(descriptor) else {
            close(descriptor)
            throw InstallError.operatingSystem("open installer authority root stream", errno)
        }
        defer { closedir(stream) }
        var names: [String] = []
        while let pointer = readdir(stream) {
            var entry = pointer.pointee
            let name = withUnsafeBytes(of: &entry.d_name) { bytes -> String in
                let values = bytes.bindMemory(to: UInt8.self)
                let end = values.firstIndex(of: 0) ?? values.endIndex
                return String(decoding: values[..<end], as: UTF8.self)
            }
            if name != ".", name != ".." {
                names.append(name)
            }
        }
        return names.sorted()
    }
}
