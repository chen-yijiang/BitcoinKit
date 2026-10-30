//
//  Psbt+Serialized.swift
//
//
//  Created by liugang zhang on 2024/4/17.
//

import Foundation
import CryptoSwift

extension Psbt {
    public static func deserialize(_ hex: String) throws -> Psbt {
        try deserialize(Data(hex: hex))
    }

    public static func deserialize(_ buffer: Data) throws -> Psbt {
        var reader = BoundedByteReader(buffer)

        guard try reader.read(UInt32.self, bigEndian: true) == 0x70736274,
              try reader.read(UInt8.self) == 0xff else {
            throw PsbtSerializeError.invalidMagicNumber
        }

        let globalMapKeyVals = try readMap(from: &reader)

        let unsignedTxMaps = globalMapKeyVals.filter { $0.key.first == PsbtGlobalTypes.UNSIGNED_TX.rawValue }
        guard unsignedTxMaps.count == 1 else {
            throw PsbtSerializeError.multiUnsignedTx
        }

        let unsigned = try Transaction.deserializeChecked(unsignedTxMaps[0].value)
        let psbt = Psbt(tx: unsigned)

        var inputKeyVals = [[PsbtKeyValue]]()
        var outputKeyVals = [[PsbtKeyValue]]()

        for _ in 0..<unsigned.inputs.count {
            inputKeyVals.append(try readMap(from: &reader))
        }

        for _ in 0..<unsigned.outputs.count {
            outputKeyVals.append(try readMap(from: &reader))
        }

        guard reader.remainingCount == 0 else { throw BoundedByteReaderError.trailingData }

        var txExist = false
        for keyVals in globalMapKeyVals {
            guard let keyType = keyVals.key.first else { throw PsbtSerializeError.unexpectedEnd }
            switch keyType {
            case PsbtGlobalTypes.UNSIGNED_TX.rawValue:
                guard !txExist else {
                    throw PsbtSerializeError.multiUnsignedTx
                }
                txExist = true
            case PsbtGlobalTypes.GLOBAL_XPUB.rawValue:
                if psbt.globalXpub == nil {
                    psbt.globalXpub = []
                }
                psbt.globalXpub?.append(try decodeGlobalXpub(keyVal: keyVals))
            default:
                if psbt.unknownKeyVals == nil {
                    psbt.unknownKeyVals = []
                }
                psbt.unknownKeyVals?.append(keyVals)
            }
        }

        for i in 0..<unsigned.inputs.count {
            psbt.inputs.append(try PsbtInputUpdate.deserialize(from: inputKeyVals[i]))
        }

        for i in 0..<unsigned.outputs.count {
            psbt.outputs.append(try PsbtOutputUpdate.deserialize(from: outputKeyVals[i]))
        }

        try psbt.validateNonWitnessUtxoOutputIndexes()

        return psbt
    }

    private static func readMap(from reader: inout BoundedByteReader) throws -> [PsbtKeyValue] {
        var seenKeys = Set<String>()
        var keyValues = [PsbtKeyValue]()

        while true {
            let key = try reader.readVarBytes()
            if key.isEmpty { return keyValues }

            let value = try reader.readVarBytes()
            let keyHex = key.hex
            guard seenKeys.insert(keyHex).inserted else {
                throw PsbtSerializeError.keyMustUnique(keyHex)
            }
            keyValues.append(PsbtKeyValue(key, value))
        }
    }
}

extension Psbt {
    public func serialized() -> Data {
        var data = Data()
        data += UInt32(0x70736274).bigEndian
        data += UInt8(0xff)
        data += serializedKeyVals().serialized()

        let inputKeyVals = inputs.map { $0.serializedKeyVals() }
        if inputKeyVals.isEmpty {
            data += UInt8(0x00)
        } else {
            inputKeyVals.forEach { data += $0.serialized() }
        }

        let outputKeyVals = outputs.map { $0.serializedKeyVals() }
        if outputKeyVals.isEmpty {
            data += UInt8(0x00)
        } else {
            outputKeyVals.forEach { data += $0.serialized() }
        }
        return data
    }

    public func serializedKeyVals() -> [PsbtKeyValue] {
        var keyVals = [PsbtKeyValue]()

        keyVals.append(PsbtKeyValue(Data([PsbtGlobalTypes.UNSIGNED_TX.rawValue]), tx.serialized()))

        if let globalXpub {
            keyVals.append(contentsOf: globalXpub.compactMap { $0.serializedKeyVal() })
        }
        return keyVals
    }
}
