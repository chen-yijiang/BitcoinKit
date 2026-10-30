//
//  Transaction.swift
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

/// tx describes a bitcoin transaction, in reply to getdata
public class Transaction {
    private static let ADVANCED_TRANSACTION_MARKER: UInt8 = 0x00
    private static let ADVANCED_TRANSACTION_FLAG: UInt8 = 0x01
    /// Transaction data format version (note, this is signed)
    public let version: UInt32
    /// If present, always 0001, and indicates the presence of witness data
    // public let flag: UInt16 // If present, always 0001, and indicates the presence of witness data
    /// Number of Transaction inputs (never zero)
    public var txInCount: VarInt {
        return VarInt(inputs.count)
    }
    /// A list of 1 or more transaction inputs or sources for coins
    public internal(set) var inputs: [TransactionInput]
    /// Number of Transaction outputs
    public var txOutCount: VarInt {
        return VarInt(outputs.count)
    }
    /// A list of 1 or more transaction outputs or destinations for coins
    public internal(set) var outputs: [TransactionOutput]
    /// A list of witnesses, one for each input; omitted if flag is omitted above
    // public let witnesses: [TransactionWitness] // A list of witnesses, one for each input; omitted if flag is omitted above
    /// The block number or timestamp at which this transaction is unlocked:
    public let lockTime: UInt32

    public var txHash: Data {
        return Crypto.sha256sha256(serialized())
    }

    public var txID: String {
        return Data(txHash.reversed()).hex
    }

    public var hasWitnesses: Bool {
        for ins in inputs {
            if ins.witness.count != 0 {
                return true
            }
        }
        return false
    }

    public init() {
        self.version = 2
        self.inputs = []
        self.outputs = []
        self.lockTime = 0
    }

    public init(version: UInt32, inputs: [TransactionInput], outputs: [TransactionOutput], lockTime: UInt32) {
        self.version = version
        self.inputs = inputs
        self.outputs = outputs
        self.lockTime = lockTime
    }

    public func addInput(_ input: TransactionInput) {
        inputs.append(input)
    }

    public func addOutput(_ output: TransactionOutput) {
        outputs.append(output)
    }

    public func serialized() -> Data {
        var data = Data()
        data += version
        if hasWitnesses {
            data += Self.ADVANCED_TRANSACTION_MARKER
            data += Self.ADVANCED_TRANSACTION_FLAG
        }
        data += txInCount.serialized()
        data += inputs.flatMap { $0.serialized() }
        data += txOutCount.serialized()
        data += outputs.flatMap { $0.serialized() }
        if hasWitnesses {
            inputs.forEach { ins in
                data += VarInt(ins.witness.count).data
                ins.witness.forEach { wit in
                    data += VarInt(wit.count).data
                    data += wit
                }
            }
        }
        data += lockTime
        return data
    }

    public func isCoinbase() -> Bool {
        return inputs.count == 1 && inputs[0].isCoinbase()
    }

    public static func deserialize(_ data: Data) -> Transaction {
        let byteStream = ByteStream(data)
        return deserialize(byteStream)
    }

    /// Deserializes a transaction while checking every read against the input length.
    /// Use this for transactions embedded in an untrusted PSBT.
    static func deserializeChecked(_ data: Data) throws -> Transaction {
        var reader = BoundedByteReader(data)
        let version = try reader.read(UInt32.self)

        let marker = try reader.read(UInt8.self)
        let flag = try reader.read(UInt8.self)
        let hasWitness = marker == Self.ADVANCED_TRANSACTION_MARKER && flag == Self.ADVANCED_TRANSACTION_FLAG
        if !hasWitness {
            try reader.rewind(by: 2)
        }

        let inputCount = try reader.readCount(minimumElementSize: 41)
        var inputs = [TransactionInput]()
        inputs.reserveCapacity(inputCount)
        for _ in 0..<inputCount {
            inputs.append(try TransactionInput.deserializeChecked(&reader))
        }

        let outputCount = try reader.readCount(minimumElementSize: 9)
        var outputs = [TransactionOutput]()
        outputs.reserveCapacity(outputCount)
        for _ in 0..<outputCount {
            outputs.append(try TransactionOutput.deserializeChecked(&reader))
        }

        if hasWitness {
            for index in inputs.indices {
                let itemCount = try reader.readCount(minimumElementSize: 1)
                var witness = [Data]()
                witness.reserveCapacity(itemCount)
                for _ in 0..<itemCount {
                    witness.append(try reader.readVarBytes())
                }
                inputs[index].witness = witness
            }
        }

        let lockTime = try reader.read(UInt32.self)
        guard reader.remainingCount == 0 else { throw BoundedByteReaderError.trailingData }
        return Transaction(version: version, inputs: inputs, outputs: outputs, lockTime: lockTime)
    }

    static func deserialize(_ byteStream: ByteStream) -> Transaction {
        let version = byteStream.read(UInt32.self)

        let maker = byteStream.read(UInt8.self)
        let flag = byteStream.read(UInt8.self)
        let hasWitness = maker == Self.ADVANCED_TRANSACTION_MARKER && flag == Self.ADVANCED_TRANSACTION_FLAG
        if !hasWitness {
            byteStream.advance(by: -2)
        }

        let txInCount = byteStream.read(VarInt.self)
        var inputs = [TransactionInput]()
        for _ in 0..<Int(txInCount.underlyingValue) {
            inputs.append(TransactionInput.deserialize(byteStream))
        }

        let txOutCount = byteStream.read(VarInt.self)
        var outputs = [TransactionOutput]()
        for _ in 0..<Int(txOutCount.underlyingValue) {
            outputs.append(TransactionOutput.deserialize(byteStream))
        }

        if hasWitness {
            for i in 0..<Int(txInCount.underlyingValue) {
                inputs[i].witness = byteStream.read([Data].self)
            }
        }

        let lockTime = byteStream.read(UInt32.self)
        return Transaction(version: version, inputs: inputs, outputs: outputs, lockTime: lockTime)
    }
}

/// VirtualSize
extension Transaction {
    public var virtualSize: Int {
        Int(ceil(Double(weight) / 4))
    }

    public var weight: Int {
        let base = byteLength(allowWitness: false);
        let total = byteLength(allowWitness: true);
        return base * 3 + total;
    }

    public func byteLength(allowWitness: Bool = true) -> Int {
        let witnesses = allowWitness && hasWitnesses
        var len = witnesses ? 10 : 8
        len += Int(VarInt(inputs.count).encodingLength)
        len += Int(VarInt(outputs.count).encodingLength)
        len += inputs.reduce(into: 0) { partialResult, input in
            partialResult += Int(input.scriptLength.encodingLength)
            partialResult += input.signatureScript.count
            partialResult += 40
        }
        len += outputs.reduce(into: 0) { partialResult, output in
            partialResult += Int(output.scriptLength.encodingLength)
            partialResult += output.lockingScript.count
            partialResult += 8
        }
        if witnesses {
            len += inputs.reduce(into: 0, { partialResult, input in
                partialResult += Int(VarInt(input.witness.count).encodingLength)
                partialResult += input.witness.reduce(into: 0, { partialResult, wit in
                    partialResult += Int(VarInt(wit.count).encodingLength)
                    partialResult += wit.count
                })
            })
        }
        return len
    }
}
