//
//  PsbtHelper.swift
//
//
//  Created by liugang zhang on 2024/4/12.
//

import Foundation

func checkKeyBuffer(keyBuf: Data, key: PsbtInputTypes) throws {
    if (keyBuf != Data([key.rawValue])) {
        throw PsbtSerializeError.invalidInputFormat(key, keyBuf)
    }
}

func checkKeyBuffer(keyBuf: Data, key: PsbtOutputTypes) throws {
    if (keyBuf != Data([key.rawValue])) {
        throw PsbtSerializeError.invalidOutputFormat(key, keyBuf)
    }
}

func witnessStackToScriptWitness(witness: [Data]) -> Data {
    var data = Data()
    data += VarInt(witness.count).serialized()
    witness.forEach {
        data += VarInt($0.count).serialized()
        data += $0
    }
    return data
}

func scriptWitnessToWitnessStack(witness: Data) -> [Data] {
    let byteStream = ByteStream(witness)
    let count = byteStream.read(VarInt.self).underlyingValue
    var vector = [Data]()
    for _ in 0..<count {
        let len = byteStream.read(VarInt.self).underlyingValue
        let value = byteStream.read(Data.self, count: Int(len))
        vector.append(value)
    }
    return vector
}

func parseScriptWitness(_ witness: Data) throws -> [Data] {
    var reader = BoundedByteReader(witness)
    let count = try reader.readCount(minimumElementSize: 1)
    var vector = [Data]()
    vector.reserveCapacity(count)
    for _ in 0..<count {
        vector.append(try reader.readVarBytes())
    }
    guard reader.remainingCount == 0 else { throw BoundedByteReaderError.trailingData }
    return vector
}

public func isValidDERKey(pubkey: Data) -> Bool {
    (pubkey.count == 33 && [2, 3].contains(pubkey.first)) ||
    (pubkey.count == 65 && 4 == pubkey.first);
}

public func isValidBIP340Key(pubkey: Data) -> Bool {
    pubkey.count == 32
}

extension Array where Element == PsbtKeyValue {
    public func serialized() -> Data {
        map { $0.serialized() } .reduce(Data(), +) + [0x00]
    }
}

extension PsbtInputUpdate {
    public var isTaprootInput: Bool {
        tapInternalKey != nil ||
        tapMerkleRoot != nil ||
        (tapLeafScript?.isEmpty == false) ||
        (tapBip32Derivation?.isEmpty == false) ||
        (witnessUtxo != nil && isP2TR(witnessUtxo!.lockingScript))
    }
}
