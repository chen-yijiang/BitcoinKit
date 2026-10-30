//
//  PsbtInputUpdate.swift
//
//
//  Created by liugang zhang on 2024/3/25.
//

import Foundation

public class PsbtInputUpdate {
    public var nonWitnessUtxo: Data?
    public var witnessUtxo: WitnessUtxo?
    public var partialSig: [PartialSig]?
    public var sighashType: UInt8?
    public var redeemScript: Data?
    public var witnessScript: Data?
    public var bip32Derivation: [Bip32Derivation]?
    public var finalScriptSig: Data?
    public var finalScriptWitness: Data?
    public var porCommitment: String?
    public var tapKeySig: Data?
    public var tapScriptSig: [TapScriptSig]?
    public var tapLeafScript: [TapLeafScript]?
    public var tapBip32Derivation: [TapBip32Derivation]?
    public var tapInternalKey: Data?
    public var tapMerkleRoot: Data?
    public var unknownKeyVals: [PsbtKeyValue]?

    public init(nonWitnessUtxo: Data? = nil, witnessUtxo: WitnessUtxo? = nil, partialSig: [PartialSig]? = nil, sighashType: UInt8? = nil, redeemScript: Data? = nil, witnessScript: Data? = nil, bip32Derivation: [Bip32Derivation]? = nil, finalScriptSig: Data? = nil, finalScriptWitness: Data? = nil, porCommitment: String? = nil, tapKeySig: Data? = nil, tapScriptSig: [TapScriptSig]? = nil, tapLeafScript: [TapLeafScript]? = nil, tapBip32Derivation: [TapBip32Derivation]? = nil, tapInternalKey: Data? = nil, tapMerkleRoot: Data? = nil, unknownKeyVals: [PsbtKeyValue]? = nil) {
        self.nonWitnessUtxo = nonWitnessUtxo
        self.witnessUtxo = witnessUtxo
        self.partialSig = partialSig
        self.sighashType = sighashType
        self.redeemScript = redeemScript
        self.witnessScript = witnessScript
        self.bip32Derivation = bip32Derivation
        self.finalScriptSig = finalScriptSig
        self.finalScriptWitness = finalScriptWitness
        self.porCommitment = porCommitment
        self.tapKeySig = tapKeySig
        self.tapScriptSig = tapScriptSig
        self.tapLeafScript = tapLeafScript
        self.tapBip32Derivation = tapBip32Derivation
        self.tapInternalKey = tapInternalKey
        self.tapMerkleRoot = tapMerkleRoot
        self.unknownKeyVals = unknownKeyVals
    }

    private let arrayOptionKeys = [
        \PsbtInputUpdate.partialSig,
        \PsbtInputUpdate.tapScriptSig,
        \PsbtInputUpdate.bip32Derivation,
        \PsbtInputUpdate.tapBip32Derivation,
    ]

    public func update<T>(key: ReferenceWritableKeyPath<PsbtInputUpdate, T?>, value: T) {
        self[keyPath: key] = value
    }

    public func update<T>(key: ReferenceWritableKeyPath<PsbtInputUpdate, [T]?>, value: [T]) {
        if arrayOptionKeys.contains(key) {
            if self[keyPath: key] == nil {
                self[keyPath: key] = []
            }
            self[keyPath: key]?.append(contentsOf: value)
        } else {
            self[keyPath: key] = value
        }
    }

    public func clearFinalizedInput() {
        partialSig = nil
        sighashType = nil
        redeemScript = nil
        witnessScript = nil
        bip32Derivation = nil
        porCommitment = nil
        tapKeySig = nil
        tapScriptSig = nil
        tapLeafScript = nil
        tapBip32Derivation = nil
        tapInternalKey = nil
        tapMerkleRoot = nil
    }

    public func serializedKeyVals() -> [PsbtKeyValue] {
        var keyVals = [PsbtKeyValue]()
        if let nonWitnessUtxo {
            keyVals.append(PsbtKeyValue(Data([PsbtInputTypes.NON_WITNESS_UTXO.rawValue]), nonWitnessUtxo))
        }
        if let witnessUtxo {
            keyVals.append(PsbtKeyValue(Data([PsbtInputTypes.WITNESS_UTXO.rawValue]), witnessUtxo.serialized()))
        }
        if let partialSig {
            keyVals.append(contentsOf: partialSig.map { $0.serializedKeyVal() })
        }
        if let sighashType {
            keyVals.append(PsbtKeyValue(Data([PsbtInputTypes.SIGHASH_TYPE.rawValue]), Data(from: UInt32(sighashType))))
        }
        if let redeemScript {
            keyVals.append(PsbtKeyValue(Data([PsbtInputTypes.REDEEM_SCRIPT.rawValue]), redeemScript))
        }
        if let witnessScript {
            keyVals.append(PsbtKeyValue(Data([PsbtInputTypes.WITNESS_SCRIPT.rawValue]), witnessScript))
        }
        if let bip32Derivation {
            keyVals.append(contentsOf: bip32Derivation.map { $0.serializedKeyVal(PsbtInputTypes.BIP32_DERIVATION.rawValue) })
        }
        if let finalScriptSig {
            keyVals.append(PsbtKeyValue(Data([PsbtInputTypes.FINAL_SCRIPTSIG.rawValue]), finalScriptSig))
        }
        if let finalScriptWitness {
            keyVals.append(PsbtKeyValue(Data([PsbtInputTypes.FINAL_SCRIPTWITNESS.rawValue]), finalScriptWitness))
        }
        if let porCommitment {
            keyVals.append(PsbtKeyValue(Data([PsbtInputTypes.POR_COMMITMENT.rawValue]), porCommitment.data(using: .utf8)!))
        }
        if let tapKeySig {
            keyVals.append(PsbtKeyValue(Data([PsbtInputTypes.TAP_KEY_SIG.rawValue]), tapKeySig))
        }
        if let tapScriptSig {
            keyVals.append(contentsOf: tapScriptSig.map { $0.serializedKeyVal() })
        }
        if let tapLeafScript {
            keyVals.append(contentsOf: tapLeafScript.map { $0.serializedKeyVal() })
        }
        if let tapBip32Derivation {
            keyVals.append(contentsOf: tapBip32Derivation.map { $0.serializedKeyVal(PsbtInputTypes.TAP_BIP32_DERIVATION.rawValue) })
        }
        if let tapInternalKey {
            keyVals.append(PsbtKeyValue(Data([PsbtInputTypes.TAP_INTERNAL_KEY.rawValue]), tapInternalKey))
        }
        if let tapMerkleRoot {
            keyVals.append(PsbtKeyValue(Data([PsbtInputTypes.TAP_MERKLE_ROOT.rawValue]), tapMerkleRoot))
        }
        return keyVals
    }

    public static func deserialize(from keyVals: [PsbtKeyValue]) throws -> PsbtInputUpdate {
        let update = PsbtInputUpdate()
        for keyVal in keyVals {
            guard let keyType = keyVal.key.first else { throw PsbtSerializeError.unexpectedEnd }
            switch PsbtInputTypes(rawValue: keyType) {
            case .NON_WITNESS_UTXO:
                try checkKeyBuffer(keyBuf: keyVal.key, key: .NON_WITNESS_UTXO)
                guard update.nonWitnessUtxo == nil else {
                    throw PsbtSerializeError.multipleInputKey(.NON_WITNESS_UTXO)
                }
                update.nonWitnessUtxo = keyVal.value
            case .WITNESS_UTXO:
                try checkKeyBuffer(keyBuf: keyVal.key, key: .WITNESS_UTXO)
                guard update.witnessUtxo == nil else {
                    throw PsbtSerializeError.multipleInputKey(.WITNESS_UTXO)
                }
                update.witnessUtxo = try TransactionOutput.deserializeChecked(keyVal.value)
            case .PARTIAL_SIG:
                if update.partialSig == nil {
                    update.partialSig = []
                }
                update.partialSig?.append(try PartialSig.deserialize(keyVal))
            case .SIGHASH_TYPE:
                try checkKeyBuffer(keyBuf: keyVal.key, key: .SIGHASH_TYPE)
                guard update.sighashType == nil else {
                    throw PsbtSerializeError.multipleInputKey(.SIGHASH_TYPE)
                }
                guard keyVal.value.count == MemoryLayout<UInt32>.size else {
                    throw PsbtSerializeError.invalidInputFormat(.SIGHASH_TYPE, keyVal.value)
                }
                var reader = BoundedByteReader(keyVal.value)
                guard let sighashType = UInt8(exactly: try reader.read(UInt32.self)) else {
                    throw PsbtSerializeError.invalidInputFormat(.SIGHASH_TYPE, keyVal.value)
                }
                update.sighashType = sighashType
            case .REDEEM_SCRIPT:
                try checkKeyBuffer(keyBuf: keyVal.key, key: PsbtInputTypes.REDEEM_SCRIPT)
                guard update.redeemScript == nil else {
                    throw PsbtSerializeError.multipleInputKey(.REDEEM_SCRIPT)
                }
                update.redeemScript = keyVal.value
            case .WITNESS_SCRIPT:
                try checkKeyBuffer(keyBuf: keyVal.key, key: PsbtInputTypes.WITNESS_SCRIPT)
                guard update.witnessScript == nil else {
                    throw PsbtSerializeError.multipleInputKey(.WITNESS_SCRIPT)
                }
                update.witnessScript = keyVal.value
            case .BIP32_DERIVATION:
                if update.bip32Derivation == nil {
                    update.bip32Derivation = []
                }
                update.bip32Derivation?.append(try Bip32Derivation.deserialize(keyVal))
            case .FINAL_SCRIPTSIG:
                try checkKeyBuffer(keyBuf: keyVal.key, key: .FINAL_SCRIPTSIG)
                update.finalScriptSig = keyVal.value
            case .FINAL_SCRIPTWITNESS:
                try checkKeyBuffer(keyBuf: keyVal.key, key: .FINAL_SCRIPTWITNESS)
                _ = try parseScriptWitness(keyVal.value)
                update.finalScriptWitness = keyVal.value
            case .POR_COMMITMENT:
                try checkKeyBuffer(keyBuf: keyVal.key, key: .POR_COMMITMENT)
                update.porCommitment = String(data: keyVal.value, encoding: .utf8)
            case .TAP_KEY_SIG:
                try checkKeyBuffer(keyBuf: keyVal.key, key: .TAP_KEY_SIG)
                guard keyVal.value.count == 64 || keyVal.value.count == 65 else {
                    throw PsbtSerializeError.invalidInputFormat(.TAP_KEY_SIG, keyVal.value)
                }
                update.tapKeySig = keyVal.value
            case .TAP_SCRIPT_SIG:
                if update.tapScriptSig == nil {
                    update.tapScriptSig = []
                }
                update.tapScriptSig?.append(try TapScriptSig.deserialize(keyVal))
            case .TAP_LEAF_SCRIPT:
                if update.tapLeafScript == nil {
                    update.tapLeafScript = []
                }
                update.tapLeafScript?.append(try TapLeafScript.deserialize(keyVal))
            case .TAP_BIP32_DERIVATION:
                if update.tapBip32Derivation == nil {
                    update.tapBip32Derivation = []
                }
                update.tapBip32Derivation?.append(try TapBip32Derivation.deserialize(keyVal))
            case .TAP_INTERNAL_KEY:
                try checkKeyBuffer(keyBuf: keyVal.key, key: PsbtInputTypes.TAP_INTERNAL_KEY)
                guard keyVal.key.count == 1, keyVal.value.count == 32 else {
                    throw PsbtSerializeError.invalidInputFormat(.TAP_INTERNAL_KEY, keyVal.value)
                }
                update.tapInternalKey = keyVal.value
            case .TAP_MERKLE_ROOT:
                try checkKeyBuffer(keyBuf: keyVal.key, key: .TAP_MERKLE_ROOT)
                guard keyVal.key.count == 1, keyVal.value.count == 32 else {
                    throw PsbtSerializeError.invalidInputFormat(.TAP_MERKLE_ROOT, keyVal.value)
                }
                update.tapMerkleRoot = keyVal.value
            default:
                if update.unknownKeyVals == nil {
                    update.unknownKeyVals = []
                }
                update.unknownKeyVals?.append(keyVal)
            }
        }
        return update
    }
}
