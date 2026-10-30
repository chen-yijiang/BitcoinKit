//
//  TransactionInput.swift
//
//  Copyright © 2018 Kishikawa Katsumi
//  Copyright © 2018 BitcoinKit developers
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//

import Foundation

public struct TransactionInput {
    /// The previous output transaction reference, as an OutPoint structure
    public let previousOutput: TransactionOutPoint
    /// The length of the signature script
    public var scriptLength: VarInt {
        return VarInt(signatureScript.count)
    }

    /// Computational Script for confirming transaction authorization
    public var signatureScript: Data
//    public let redeemScript: Data?

    public var witness: [Data]
    /// Transaction version as defined by the sender. Intended for "replacement" of transactions when information is updated before inclusion into a block.
    public var sequence: UInt32

    public init(previousOutput: TransactionOutPoint, sequence: UInt32 = UInt32.max, signatureScript: Data? = nil, witness: [Data]? = nil) {
        self.previousOutput = previousOutput
        self.signatureScript = signatureScript ?? Data()
        self.sequence = sequence
        self.witness = witness ?? []
//        self.redeemScript = redeemScript
    }

    public func isCoinbase() -> Bool {
        return previousOutput.hash == Data(count: 32)
            && previousOutput.index == 0xFFFF_FFFF
    }

    public func serialized() -> Data {
        var data = Data()
        data += previousOutput.serialized()
        data += scriptLength.serialized()
        data += signatureScript
        data += sequence
        return data
    }

    static func deserialize(_ byteStream: ByteStream) -> TransactionInput {
        let previousOutput = TransactionOutPoint.deserialize(byteStream)
        let scriptLength = byteStream.read(VarInt.self)
        let signatureScript = byteStream.read(Data.self, count: Int(scriptLength.underlyingValue))
        let sequence = byteStream.read(UInt32.self)
        return TransactionInput(previousOutput: previousOutput, sequence: sequence, signatureScript: signatureScript)
    }

    static func deserializeChecked(_ reader: inout BoundedByteReader) throws -> TransactionInput {
        let previousOutput = try TransactionOutPoint.deserializeChecked(&reader)
        let signatureScript = try reader.readVarBytes()
        let sequence = try reader.read(UInt32.self)
        return TransactionInput(previousOutput: previousOutput, sequence: sequence, signatureScript: signatureScript)
    }
}

extension TransactionInput {
//    var utxo: TransactionOutput {
//        if let witnessUtxo = update.witnessUtxo {
//            return witnessUtxo
//        } else if let nonWitnessUtxo = update.nonWitnessUtxo {
//            let tx = Transaction.deserialize(nonWitnessUtxo)
//            return tx.outputs[Int(previousOutput.index)]
//        } else {
//            fatalError()
//        }
//    }
//
//    var isTaprootInput: Bool {
//        update.tapInternalKey != nil ||
//        update.tapMerkleRoot != nil ||
//        (update.tapLeafScript?.isEmpty == false) ||
//        (update.tapBip32Derivation?.isEmpty == false) ||
//        (update.witnessUtxo != nil && isP2TR(update.witnessUtxo!.lockingScript))
//    }
//
//    var isP2SH: Bool {
//        update.redeemScript != nil
//    }
//
//    var isP2WSH: Bool {
//        update.witnessScript != nil
//    }
//
//    var isSegwit: Bool {
//        isP2WSH || isP2WPKH(script)
//    }
//
//    var script: Data {
//        if let redeemScript = update.redeemScript {
//            return redeemScript
//        } else if let witnessScript = update.witnessScript {
//            return witnessScript
//        } else {
//            return utxo.lockingScript
//        }
//    }
}
