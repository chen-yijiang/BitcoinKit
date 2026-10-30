//
//  PsbtGlobalTypes.swift
//
//
//  Created by liugang zhang on 2024/3/26.
//

import Foundation

public enum PsbtGlobalTypes: UInt8, CaseIterable {
  case UNSIGNED_TX
  case GLOBAL_XPUB
}

public struct GlobalXPub {
    public let extendedPubkey: Data
    public let masterFingerprint: Data
    public let path: String;

    public func serializedKeyVal() -> PsbtKeyValue {
        let head = PsbtGlobalTypes.GLOBAL_XPUB.rawValue
        let key: Data = [head] + extendedPubkey

        let splitPath = path.split(separator: "/")
        var value = masterFingerprint
        splitPath[1...].forEach { s in
            let isHard = s.last == "'"
            var num = 0x7fffffff & (UInt32(isHard ? s.dropLast() : s, radix: 10) ?? 0)
            if isHard {
                num += 0x80000000
            }
            value += num
        }
        return PsbtKeyValue(key, value)
    }
}

func decodeGlobalXpub(keyVal: PsbtKeyValue) throws -> GlobalXPub {
    guard keyVal.key.count == 79,
          [2, 3].contains(keyVal.key[46]),
          keyVal.value.count >= 4,
          (keyVal.value.count - 4) % 4 == 0 else {
        throw PsbtSerializeError.unexpectedEnd
    }
    let pubkey = keyVal.key[1...]
    var path = "m"
    for i in 0..<((keyVal.value.count - 4) / 4) {
        var reader = BoundedByteReader(Data(keyVal.value[(i * 4 + 4)..<(i * 4 + 8)]))
        let val = try reader.read(UInt32.self)
        let isHard = (val & 0x80000000) != 0
        let idx = val & 0x7fffffff
        path += "/"
        path += String(idx, radix: 10)
        isHard ? path +=  "'" : ()
    }
    return .init(extendedPubkey: pubkey,
                 masterFingerprint: Data(keyVal.value[0..<4]),
                 path: path)
}
