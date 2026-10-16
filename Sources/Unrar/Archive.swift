// SPDX-FileCopyrightText: 2021 mtgto <hogerappa@gmail.com>
// SPDX-License-Identifier: MIT

import Cunrar
import Foundation

// unrar's LPARAM is `#define`d as `long`: 64 bits on macOS/Linux, but 32 bits
// on Windows (LLP64). Name the platform's LPARAM width once for the
// conversions below.
#if os(Windows)
typealias UnrarLPARAM = Int32
#else
typealias UnrarLPARAM = Int
#endif

/// Routes UNRARCALLBACK's `UserData` through a small-integer table instead of a
/// raw object pointer: on Windows the 32-bit LPARAM cannot hold a 64-bit
/// pointer, so passing the `Callback` object directly would truncate it and
/// crash when the callback fires. The table keeps the object alive for the
/// duration of the extraction and behaves identically on every platform.
private final class CallbackRegistry: @unchecked Sendable {
    static let shared = CallbackRegistry()

    private let lock = NSLock()
    private var nextID: Int32 = 1
    private var table: [Int32: Archive.Callback] = [:]

    private init() {}

    func register(_ callback: Archive.Callback) -> Int32 {
        lock.lock()
        defer { lock.unlock() }
        let id = nextID
        nextID = nextID == .max ? 1 : nextID + 1
        table[id] = callback
        return id
    }

    func callback(for id: Int32) -> Archive.Callback? {
        lock.lock()
        defer { lock.unlock() }
        return table[id]
    }

    func unregister(_ id: Int32) {
        lock.lock()
        defer { lock.unlock() }
        table.removeValue(forKey: id)
    }
}

// NOTE: This class is not thread safe.
public struct Archive: Sendable {
    public let fileURL: URL
    public let password: String?
    public let isVolume: Bool
    public let hasComment: Bool  // maximum comment size = 0x40000 (MAXCMTSIZE in rardefs.hpp)
    public let isHeaderEncrypted: Bool
    public let isFirstVolume: Bool

    public init(path: String, password: String? = nil) throws {
        try self.init(fileURL: URL(fileURLWithPath: path), password: password)
    }

    public init(fileURL: URL, password: String? = nil) throws {
        self.fileURL = fileURL
        self.password = password

        var flags = RAROpenArchiveDataEx()
        flags.OpenMode = UInt32(RAR_OM_LIST)
        flags.CmtBuf = nil
        flags.CmtBufW = nil
        flags.CmtBufSize = 0

        guard let data = Archive.open(fileURL: fileURL, password: password, flags: &flags) else {
            throw UnrarError.badArchive
        }
        defer {
            RARCloseArchive(data)
        }
        if flags.OpenResult != ERAR_SUCCESS {
            throw UnrarError.badArchive
        }
        self.isVolume = flags.Flags & UInt32(ROADF_VOLUME) != 0
        self.hasComment = flags.Flags & UInt32(ROADF_COMMENT) != 0
        self.isHeaderEncrypted = flags.Flags & UInt32(ROADF_ENCHEADERS) != 0
        self.isFirstVolume = flags.Flags & UInt32(ROADF_FIRSTVOLUME) != 0
    }

    public func entries() throws -> [Entry] {
        var entries: [Entry] = []
        var flags = RAROpenArchiveDataEx()
        flags.OpenMode = UInt32(RAR_OM_LIST)
        flags.CmtBuf = nil
        flags.CmtBufW = nil
        flags.CmtBufSize = 0

        var header = RARHeaderDataEx()
        guard let data = Archive.open(fileURL: self.fileURL, password: self.password, flags: &flags) else {
            throw UnrarError.badArchive
        }
        defer {
            RARCloseArchive(data)
        }
        if flags.OpenResult != ERAR_SUCCESS {
            throw UnrarError.badArchive
        }
        loop: repeat {
            let result = RARReadHeaderEx(data, &header)
            switch result {
            case ERAR_SUCCESS:
                entries.append(Entry(header))
            case ERAR_END_ARCHIVE:
                break loop
            default:
                throw UnrarError.fromErrorCode(result)
            }
        } while RARProcessFile(data, RAR_SKIP, nil, nil) == ERAR_SUCCESS

        return entries
    }

    public func comment() throws -> String {
        var flags = RAROpenArchiveDataEx()
        flags.OpenMode = UInt32(RAR_OM_LIST)
        let buffer = UnsafeMutablePointer<Int8>.allocate(capacity: 0x40001)
        flags.CmtBuf = buffer
        flags.CmtBufW = nil
        flags.CmtBufSize = 0x40001

        guard let data = Archive.open(fileURL: self.fileURL, password: self.password, flags: &flags) else {
            throw UnrarError.badArchive
        }
        defer {
            RARCloseArchive(data)
        }
        if flags.OpenResult != ERAR_SUCCESS {
            throw UnrarError.badArchive
        }
        if flags.CmtState == ERAR_SMALL_BUF {
            // TODO: Update comment buffer size
            throw UnrarError.unknownFormat
        }
        if flags.Flags & UInt32(ROADF_COMMENT) == 0 {
            return ""
        }
        return String(cString: buffer)
    }

    class Callback {
        let callback: (Data, Progress) -> Void
        let progress: Progress

        init(_ uncompressedSize: UInt64, _ callback: @escaping (Data, Progress) -> Void) {
            self.callback = callback
            self.progress = Progress(totalUnitCount: Int64(uncompressedSize))
        }
    }

    public func extract(_ entry: Entry, handler: @escaping (Data, Progress) -> Void) throws {
        if entry.uncompressedSize == 0 {
            let progress = Progress(totalUnitCount: 1)
            progress.completedUnitCount = 1
            handler(Data(), progress)
            return
        }
        // See CallbackRegistry: the C callback cannot carry the object pointer on
        // Windows (32-bit LPARAM), so it carries a registry ID instead.
        let stateID = CallbackRegistry.shared.register(Callback(entry.uncompressedSize, handler))
        defer { CallbackRegistry.shared.unregister(stateID) }
        let callback: UNRARCALLBACK = { msg, userData, p1, p2 in
            // `userData` is the registry ID. Int32(userData) compiles on every
            // platform: LPARAM is Int32 on Windows, Int on macOS/Linux.
            guard let state = CallbackRegistry.shared.callback(for: Int32(userData)) else {
                return 0
            }
            switch msg {
            // UNRARCALLBACK_MESSAGES imports with a platform ABI-dependent raw
            // type (unsigned on macOS/Linux, signed on Windows): convert to
            // UInt32 to compare against `msg` (UINT) on every platform.
            case UInt32(UCM_PROCESSDATA.rawValue):
                // p1/p2 are LPARAM (32-bit on Windows, 64-bit elsewhere):
                // widen to Int once for the pointer/count conversions below.
                let p1 = Int(p1)
                let p2 = Int(p2)
                if let ptr = UnsafeRawPointer(bitPattern: p1) {
                    let data = Data(bytes: ptr, count: p2)
                    state.progress.completedUnitCount += Int64(p2)
                    state.callback(data, state.progress)
                    if state.progress.isCancelled {
                        return -1
                    }
                }
            case UInt32(UCM_NEEDPASSWORD.rawValue),
                 UInt32(UCM_NEEDPASSWORDW.rawValue):
                // TODO ?
                break
            default:
                // TODO error handling
                break
            }
            return 0
        }
        var flags = RAROpenArchiveDataEx()
        flags.OpenMode = UInt32(RAR_OM_EXTRACT)
        flags.CmtBuf = nil
        flags.CmtBufSize = 0
        var header = RARHeaderDataEx()
        guard let data = Archive.open(fileURL: self.fileURL, password: self.password, flags: &flags) else {
            throw UnrarError.badArchive
        }
        defer {
            RARCloseArchive(data)
        }
        loop: repeat {
            let result = RARReadHeaderEx(data, &header)
            switch result {
            case ERAR_SUCCESS:
                // compare fileName
                if Entry(header) == entry {
                    RARSetCallback(data, callback, UnrarLPARAM(stateID))
                    let result = RARProcessFile(data, RAR_OM_EXTRACT, nil, nil)
                    RARSetCallback(data, nil, 0)
                    if result != ERAR_SUCCESS {
                        throw UnrarError.fromErrorCode(result)
                    }
                    break loop
                }
            case ERAR_END_ARCHIVE:
                // Not found
                break loop
            default:
                throw UnrarError.fromErrorCode(result)
            }
        } while RARProcessFile(data, RAR_SKIP, nil, nil) == ERAR_SUCCESS
    }

    public func extract(_ entry: Entry) throws -> Data {
        var fullData = Data(capacity: Int(entry.uncompressedSize))
        try self.extract(entry) { (data, progress) in
            fullData.append(data)
        }
        if fullData.count == entry.uncompressedSize {
            return fullData
        } else {
            throw UnrarError.unknown
        }
    }

    private static func open(fileURL: URL, password: String?, flags: inout RAROpenArchiveDataEx) -> UnsafeMutableRawPointer? {
        guard
            let ptr = fileURL.path.utf8CString.withUnsafeBufferPointer({ (ptr) -> UnsafeMutableRawPointer? in
                flags.ArcName = UnsafeMutablePointer(mutating: ptr.baseAddress)
                return UnsafeMutableRawPointer(RAROpenArchiveEx(&flags))
            })
        else {
            return nil
        }
        if let password = password {
            password.utf8CString.withUnsafeBufferPointer({ (passwordPtr) -> Void in
                RARSetPassword(ptr, UnsafeMutablePointer(mutating: passwordPtr.baseAddress))
            })
        }
        return ptr
    }
}
