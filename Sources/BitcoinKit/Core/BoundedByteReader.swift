import Foundation

enum BoundedByteReaderError: Error, Equatable {
    case insufficientData(expected: Int, remaining: Int)
    case invalidLength
    case nonCanonicalCompactSize
    case trailingData
}

/// A bounds-checked reader for serialized data supplied by untrusted peers or dApps.
struct BoundedByteReader {
    private let data: Data
    private(set) var offset: Int

    var remainingCount: Int {
        data.endIndex - offset
    }

    init(_ data: Data) {
        self.data = data
        self.offset = data.startIndex
    }

    mutating func readBytes(count: Int) throws -> Data {
        guard count >= 0 else {
            throw BoundedByteReaderError.invalidLength
        }
        guard count <= remainingCount else {
            throw BoundedByteReaderError.insufficientData(expected: count, remaining: remainingCount)
        }

        let end = offset + count
        let bytes = Data(data[offset..<end])
        offset = end
        return bytes
    }

    mutating func read<T: FixedWidthInteger>(_ type: T.Type, bigEndian: Bool = false) throws -> T {
        let bytes = try readBytes(count: MemoryLayout<T>.size)
        let rawValue = bytes.to(type: type)
        return bigEndian ? T(bigEndian: rawValue) : T(littleEndian: rawValue)
    }

    mutating func readCompactSize() throws -> UInt64 {
        let marker = try read(UInt8.self)
        switch marker {
        case 0...252:
            return UInt64(marker)
        case 0xfd:
            let value = UInt64(try read(UInt16.self))
            guard value >= 0xfd else { throw BoundedByteReaderError.nonCanonicalCompactSize }
            return value
        case 0xfe:
            let value = UInt64(try read(UInt32.self))
            guard value > UInt64(UInt16.max) else { throw BoundedByteReaderError.nonCanonicalCompactSize }
            return value
        case 0xff:
            let value = try read(UInt64.self)
            guard value > UInt64(UInt32.max) else { throw BoundedByteReaderError.nonCanonicalCompactSize }
            return value
        default:
            throw BoundedByteReaderError.invalidLength
        }
    }

    mutating func readCount(minimumElementSize: Int = 0) throws -> Int {
        guard minimumElementSize >= 0 else { throw BoundedByteReaderError.invalidLength }
        guard let count = Int(exactly: try readCompactSize()) else {
            throw BoundedByteReaderError.invalidLength
        }
        if minimumElementSize > 0 && count > remainingCount / minimumElementSize {
            throw BoundedByteReaderError.insufficientData(expected: count, remaining: remainingCount)
        }
        return count
    }

    mutating func readVarBytes() throws -> Data {
        guard let count = Int(exactly: try readCompactSize()) else {
            throw BoundedByteReaderError.invalidLength
        }
        return try readBytes(count: count)
    }

    mutating func readRemainingBytes() throws -> Data {
        try readBytes(count: remainingCount)
    }

    mutating func rewind(by count: Int) throws {
        guard count >= 0, count <= offset - data.startIndex else {
            throw BoundedByteReaderError.invalidLength
        }
        offset -= count
    }
}
