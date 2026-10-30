import XCTest
@testable import BitcoinKit

final class PsbtBoundsTests: XCTestCase {
    func testEveryTruncatedPrefixOfValidPsbtThrows() throws {
        let psbt = Psbt()
        psbt.addInput(prevOutput: TransactionOutPoint(hash: Data(repeating: 0x11, count: 32), index: 0))
        psbt.addOutput(output: TransactionOutput(value: 1, lockingScript: Data([0x51])))
        let serialized = psbt.serialized()
        XCTAssertNoThrow(try Psbt.deserialize(serialized))

        for length in 0..<serialized.count {
            XCTAssertThrowsError(try Psbt.deserialize(Data(serialized.prefix(length))), "prefix length \(length)")
        }
    }

    func testValidMagicWithTruncatedMapValueThrows() {
        XCTAssertThrowsError(try Psbt.deserialize("70736274ff0100"))
    }

    func testTruncatedUnsignedTransactionThrows() throws {
        let transaction = Transaction(
            version: 2,
            inputs: [TransactionInput(previousOutput: TransactionOutPoint(hash: Data(repeating: 0x22, count: 32), index: 0))],
            outputs: [TransactionOutput(value: 1, lockingScript: Data([0x51]))],
            lockTime: 0
        )
        let truncatedTransaction = Data(transaction.serialized().dropLast())
        var psbt = Data([0x70, 0x73, 0x62, 0x74, 0xff])
        psbt.append([PsbtKeyValue(Data([PsbtGlobalTypes.UNSIGNED_TX.rawValue]), truncatedTransaction)].serialized())

        XCTAssertThrowsError(try Psbt.deserialize(psbt))
    }

    func testNonWitnessUtxoOutputIndexIsCheckedDuringPsbtParsing() throws {
        let previousTransaction = Transaction(
            version: 1,
            inputs: [TransactionInput(previousOutput: TransactionOutPoint(hash: Data(repeating: 0x33, count: 32), index: 0))],
            outputs: [TransactionOutput(value: 10, lockingScript: Data([0x51]))],
            lockTime: 0
        )
        let malformed = Psbt()
        malformed.addInput(
            prevOutput: TransactionOutPoint(hash: previousTransaction.txHash, index: 1),
            update: PsbtInputUpdate(nonWitnessUtxo: previousTransaction.serialized())
        )
        malformed.addOutput(output: TransactionOutput(value: 1, lockingScript: Data([0x51])))

        XCTAssertThrowsError(try Psbt.deserialize(malformed.serialized()))
    }

    func testSigningAndFeeCalculationThrowForOutOfRangePreviousOutput() throws {
        let previousTransaction = Transaction(
            version: 1,
            inputs: [TransactionInput(previousOutput: TransactionOutPoint(hash: Data(repeating: 0x44, count: 32), index: 0))],
            outputs: [TransactionOutput(value: 10, lockingScript: Data([0x51]))],
            lockTime: 0
        )
        let malformed = Psbt()
        malformed.addInput(
            prevOutput: TransactionOutPoint(hash: previousTransaction.txHash, index: 1),
            update: PsbtInputUpdate(nonWitnessUtxo: previousTransaction.serialized())
        )
        malformed.addOutput(output: TransactionOutput(value: 1, lockingScript: Data([0x51])))

        XCTAssertThrowsError(try malformed.signInput(with: PrivateKey(), at: 0))
        XCTAssertThrowsError(try malformed.calculateFee())
        XCTAssertEqual(malformed.fee, 0)
    }

}
