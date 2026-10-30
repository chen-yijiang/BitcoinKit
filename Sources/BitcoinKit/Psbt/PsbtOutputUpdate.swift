//
//  PsbtOutputUpdate.swift
//
//
//  Created by liugang zhang on 2024/3/25.
//

import Foundation

public class PsbtOutputUpdate {
    public var redeemScript: Data?
    public var witnessScript: Data?
    public var bip32Derivation: [Bip32Derivation]?
    public var tapInternalKey: Data?
    public var tapTree: TapTree?
    public var tapBip32Derivation: [TapBip32Derivation]?
    public var unknownKeyVals: [PsbtKeyValue]?

    public init(redeemScript: Data? = nil, witnessScript: Data? = nil, bip32Derivation: [Bip32Derivation]? = nil, tapInternalKey: Data? = nil, tapTree: TapTree? = nil, tapBip32Derivation: [TapBip32Derivation]? = nil, unknownKeyVals: [PsbtKeyValue]? = nil) {
        self.redeemScript = redeemScript
        self.witnessScript = witnessScript
        self.bip32Derivation = bip32Derivation
        self.tapInternalKey = tapInternalKey
        self.tapTree = tapTree
        self.tapBip32Derivation = tapBip32Derivation
        self.unknownKeyVals = unknownKeyVals
    }

    public func serializedKeyVals() -> [PsbtKeyValue] {
        var keyVals = [PsbtKeyValue]()
        if let redeemScript {
            keyVals.append(PsbtKeyValue(Data([PsbtOutputTypes.REDEEM_SCRIPT.rawValue]), redeemScript))
        }
        if let witnessScript {
            keyVals.append(PsbtKeyValue(Data([PsbtOutputTypes.WITNESS_SCRIPT.rawValue]), witnessScript))
        }
        if let bip32Derivation {
            keyVals.append(contentsOf: bip32Derivation.map { $0.serializedKeyVal(PsbtOutputTypes.BIP32_DERIVATION.rawValue) })
        }
        if let tapInternalKey {
            keyVals.append(PsbtKeyValue(Data([PsbtOutputTypes.TAP_INTERNAL_KEY.rawValue]), tapInternalKey))
        }
        if let tapTree {
            keyVals.append(tapTree.serializedKeyVal())
        }
        if let tapBip32Derivation {
            keyVals.append(contentsOf: tapBip32Derivation.map { $0.serializedKeyVal(PsbtOutputTypes.TAP_BIP32_DERIVATION.rawValue) })
        }
        return keyVals
    }

    public static func deserialize(from keyVals: [PsbtKeyValue]) throws -> PsbtOutputUpdate {
        let update = PsbtOutputUpdate()
        for keyVal in keyVals {
            guard let keyType = keyVal.key.first else { throw PsbtSerializeError.unexpectedEnd }
            switch PsbtOutputTypes(rawValue: keyType) {
            case .REDEEM_SCRIPT:
                try checkKeyBuffer(keyBuf: keyVal.key, key: PsbtOutputTypes.REDEEM_SCRIPT)
                guard update.redeemScript == nil else {
                    throw PsbtSerializeError.multipleOutputKey(.REDEEM_SCRIPT)
                }
                update.redeemScript = keyVal.value
            case .WITNESS_SCRIPT:
                try checkKeyBuffer(keyBuf: keyVal.key, key: PsbtOutputTypes.WITNESS_SCRIPT)
                guard update.witnessScript == nil else {
                    throw PsbtSerializeError.multipleOutputKey(.WITNESS_SCRIPT)
                }
                update.witnessScript = keyVal.value
            case .BIP32_DERIVATION:
                if update.bip32Derivation == nil {
                    update.bip32Derivation = []
                }
                update.bip32Derivation?.append(try Bip32Derivation.deserialize(keyVal))
            case .TAP_INTERNAL_KEY:
                try checkKeyBuffer(keyBuf: keyVal.key, key: PsbtOutputTypes.TAP_INTERNAL_KEY)
                guard keyVal.key.count == 1, keyVal.value.count == 32 else {
                    throw PsbtSerializeError.invalidInputFormat(.TAP_INTERNAL_KEY, keyVal.value)
                }
                update.tapInternalKey = keyVal.value
            case .TAP_TREE:
                try checkKeyBuffer(keyBuf: keyVal.key, key: PsbtOutputTypes.TAP_TREE)
                update.tapTree = try TapTree.deserialize(keyVal)
            case .TAP_BIP32_DERIVATION:
                if update.tapBip32Derivation == nil {
                    update.tapBip32Derivation = []
                }
                update.tapBip32Derivation?.append(try TapBip32Derivation.deserialize(keyVal))
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
