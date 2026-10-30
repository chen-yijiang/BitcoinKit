//
//  PsbtInterface.swift
//
//
//  Created by liugang zhang on 2024/3/25.
//

import Foundation

public struct PsbtKeyValue {
    public let key: Data
    public let value: Data

    public init(_ key: Data, _ value: Data) {
        self.key = key
        self.value = value
    }

    public func serialized() -> Data {
        VarInt(key.count).serialized() + key + VarInt(value.count).serialized() + value
    }
}

public struct TapLeaf {
    public let leafVersion: UInt8
    public let script: Data
    public let depth: UInt8

    public init(leafVersion: UInt8, script: Data, depth: UInt8) {
        self.leafVersion = leafVersion
        self.script = script
        self.depth = depth
    }
}

public struct TapTree {
    public let leaves: [TapLeaf]

    public init(leaves: [TapLeaf]) {
        self.leaves = leaves
    }

    func serializedKeyVal() -> PsbtKeyValue {
        let key = Data([PsbtOutputTypes.TAP_TREE.rawValue])
        var data = Data()
        leaves.forEach { leaf in
            data += leaf.depth
            data += leaf.leafVersion
            data += VarInt(leaf.script.count).serialized()
            data += leaf.script
        }
        return PsbtKeyValue(key, data)
    }

    public static func deserialize(_ keyVal: PsbtKeyValue) throws -> TapTree {
        var reader = BoundedByteReader(keyVal.value)
        var vector = [TapLeaf]()
        while reader.remainingCount > 0 {
            let depth = try reader.read(UInt8.self)
            let leafVersion = try reader.read(UInt8.self)
            let script = try reader.readVarBytes()
            vector.append(
                .init(leafVersion: leafVersion, script: script, depth: depth)
            )
        }

        return .init(leaves: vector)
    }
}

public struct TapScriptSig {
    public let pubKey: Data
    public let signature: Data
    public let leafHash: Data

    public init(pubKey: Data, signature: Data, leafHash: Data) {
        self.pubKey = pubKey
        self.signature = signature
        self.leafHash = leafHash
    }

    func serializedKeyVal() -> PsbtKeyValue {
        let key: Data = [PsbtInputTypes.TAP_SCRIPT_SIG.rawValue] + pubKey + leafHash
        return PsbtKeyValue(key, signature)
    }

    public static func deserialize(_ keyVal: PsbtKeyValue) throws -> TapScriptSig {
        guard keyVal.key.count == 65, keyVal.value.count != 64, keyVal.value.count != 65 else {
            throw PsbtSerializeError.invalidInputFormat(.TAP_SCRIPT_SIG, keyVal.key)
        }
        return .init(pubKey: keyVal.key[1..<33], signature: keyVal.key[33...], leafHash: keyVal.value)
    }
}

public struct TapLeafScript {
    public let leafVersion: UInt8
    public let script: Data
    public let controlBlock: Data

    public init(leafVersion: UInt8, script: Data, controlBlock: Data) {
        self.leafVersion = leafVersion
        self.script = script
        self.controlBlock = controlBlock
    }

    func serializedKeyVal() -> PsbtKeyValue {
        let key: Data = [PsbtInputTypes.TAP_LEAF_SCRIPT.rawValue] + controlBlock
        let value = script + [leafVersion]
        return PsbtKeyValue(key, value)
    }

    public static func deserialize(_ keyVal: PsbtKeyValue) throws -> TapLeafScript {
        guard keyVal.key.count >= 34,
              (keyVal.key.count - 34) % 32 == 0,
              !keyVal.value.isEmpty else {
            throw PsbtSerializeError.invalidInputFormat(.TAP_LEAF_SCRIPT, keyVal.key)
        }
        let leafVersion = keyVal.value.last!
        guard keyVal.key[1] & 0xfe == leafVersion else {
            throw PsbtSerializeError.invalidInputFormat(.TAP_LEAF_SCRIPT, keyVal.key)
        }
        let script = keyVal.value[0..<(keyVal.value.count - 1)]
        let block = keyVal.key[1...]
        return .init(leafVersion: leafVersion, script: script, controlBlock: block)
    }
}

public struct PartialSig {
    public let pubkey: Data
    public let signature: Data

    public init(pubkey: Data, signature: Data) {
        self.pubkey = pubkey
        self.signature = signature
    }

    func serializedKeyVal() -> PsbtKeyValue {
        return PsbtKeyValue([PsbtInputTypes.PARTIAL_SIG.rawValue] + pubkey, signature)
    }

    public static func deserialize(_ keyVal: PsbtKeyValue) throws -> PartialSig {
        if (
            !(keyVal.key.count == 34 || keyVal.key.count == 66) ||
            ![2, 3, 4].contains(keyVal.key[1])
        ) {
            throw PsbtSerializeError.invalidInputFormat(.PARTIAL_SIG, keyVal.key)
        }
        let pubkey = keyVal.key[1...];
        return .init(pubkey: pubkey, signature: keyVal.value)
    }
}

public struct Bip32Derivation {
    public let masterFingerprint: Data
    public let pubkey: Data
    public let path: String

    public init(masterFingerprint: Data, pubkey: Data, path: String) {
        self.masterFingerprint = masterFingerprint
        self.pubkey = pubkey
        self.path = path
    }

    func serializedKeyVal(_ byte: UInt8) -> PsbtKeyValue {
        let key: Data = [byte] + pubkey

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

    public static func deserialize(_ keyVal: PsbtKeyValue, isValid: (Data) -> Bool = isValidDERKey) throws -> Bip32Derivation {
        guard keyVal.key.count > 1,
              keyVal.value.count >= 4,
              (keyVal.value.count - 4) % 4 == 0 else {
            throw PsbtSerializeError.invalidInputFormat(.BIP32_DERIVATION, keyVal.key)
        }
        let pubkey = keyVal.key[1...]
        guard isValid(Data(pubkey)) else {
            throw PsbtSerializeError.invalidInputFormat(.BIP32_DERIVATION, keyVal.key)
        }
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
        return .init(masterFingerprint: Data(keyVal.value[0..<4]), pubkey: Data(pubkey), path: path)
    }
}

public struct TapBip32Derivation {
    public let masterFingerprint: Data
    public let pubkey: Data
    public let path: String
    public let leafHashes: [Data]

    public init(masterFingerprint: Data, pubkey: Data, path: String, leafHashes: [Data]) {
        self.masterFingerprint = masterFingerprint
        self.pubkey = pubkey
        self.path = path
        self.leafHashes = leafHashes
    }

    public init(bip32Derivation: Bip32Derivation, leafHashes: [Data]) {
        self.masterFingerprint = bip32Derivation.masterFingerprint
        self.pubkey = bip32Derivation.pubkey
        self.path = bip32Derivation.path
        self.leafHashes = leafHashes
    }

    func serializedKeyVal(_ byte: UInt8) -> PsbtKeyValue {
        let base = Bip32Derivation(masterFingerprint: masterFingerprint, pubkey: pubkey, path: path).serializedKeyVal(byte)
        var data = VarInt(leafHashes.count).serialized()
        leafHashes.forEach { data += $0 }
        data += base.value
        return PsbtKeyValue(base.key, data)
    }

    public static func deserialize(_ keyVal: PsbtKeyValue) throws -> TapBip32Derivation {
        var reader = BoundedByteReader(keyVal.value)
        let hashCount = try reader.readCount(minimumElementSize: 32)
        var leafHashes = [Data]()
        leafHashes.reserveCapacity(hashCount)
        for _ in 0..<hashCount {
            leafHashes.append(try reader.readBytes(count: 32))
        }
        let derivationValue = try reader.readRemainingBytes()
        let bip32Derivation = try Bip32Derivation.deserialize(
            PsbtKeyValue(keyVal.key, derivationValue),
            isValid: isValidBIP340Key
        )
        return .init(bip32Derivation: bip32Derivation, leafHashes: leafHashes)
    }
}
