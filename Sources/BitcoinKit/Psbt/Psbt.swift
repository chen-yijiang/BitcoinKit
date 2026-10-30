//
//  Psbt.swift
//
//
//  Created by liugang zhang on 2024/4/10.
//

import Foundation

/// The `Psbt` class represents a Partially Signed Bitcoin Transaction (PSBT).
public class Psbt {
    public internal(set) var tx: Transaction
    public internal(set) var globalXpub: [GlobalXPub]?
    public internal(set) var unknownKeyVals: [PsbtKeyValue]?

    public internal(set) var inputs: [PsbtInputUpdate]
    public internal(set) var outputs: [PsbtOutputUpdate]

    public init(tx: Transaction = Transaction()) {
        self.tx = tx
        self.inputs = []
        self.outputs = []
    }

    /// Adds an input to the Partially Signed Bitcoin Transaction (PSBT).
    ///
    /// - Parameters:
    ///   - prevOutput: The previous output of the transaction being spent.
    ///   - sequence: The sequence number for the input. Defaults to UInt32.max.
    ///   - update: An optional `PsbtInputUpdate` object containing additional information about the input.
    public func addInput(prevOutput: TransactionOutPoint, sequence: UInt32 = UInt32.max, update: PsbtInputUpdate = PsbtInputUpdate()) {
        tx.addInput(.init(previousOutput: prevOutput, sequence: sequence))
        inputs.append(update)
    }

    public func addOutput(output: TransactionOutput, update: PsbtOutputUpdate = PsbtOutputUpdate()) {
        tx.addOutput(output)
        outputs.append(update)
    }

    public func signAllInputs(with pk: PrivateKey, sigHashTypes: [BTCSighashType]? = nil) throws {
        for i in 0..<inputs.count {
            try signInput(with: pk, at: i, sigHashTypes: sigHashTypes)
        }
    }

    public func signInput(with pk: PrivateKey, at index: Int, sigHashTypes: [BTCSighashType]? = nil) throws {
        guard inputs.indices.contains(index), tx.inputs.indices.contains(index) else {
            throw PsbtError.indexOutOfBounds
        }
        if inputs[index].isTaprootInput {
            try _signTaprootInput(with: pk, at: index, sigHashTypes: sigHashTypes)
        } else {
            if let sigHashTypes {
                try _signInput(with: pk, at: index, sigHashTypes: sigHashTypes)
            } else {
                try _signInput(with: pk, at: index)
            }
        }
    }

    private func _signInput(with pk: PrivateKey, at index: Int, sigHashTypes: [BTCSighashType] = [.ALL]) throws {
        let (hash, sigHashType) = try getHashForSig(index: index, sigHashTypes: sigHashTypes)
        let signature: Data = try Crypto.sign(hash, privateKey: pk)
        let partialSig = PartialSig(pubkey: pk.publicKey().data, signature: signature + [sigHashType.rawValue])
        inputs[index].update(key: \.partialSig, value: [partialSig])
    }

    private func _signTaprootInput(with pk: PrivateKey, at index: Int, sigHashTypes: [BTCSighashType]?) throws {
        let hashesForSig = try getTaprootHashesForSig(inputIndex: index, publicKey: pk.publicKey().data)
        let tapKeySig = try hashesForSig.filter { $0.leafHash == nil }
            .map { hash, _ in
                let signature = try Crypto.signSchnorr(hash, with: pk)
                return serializeTaprootSignature(sig: signature, sighashType: nil)
            }.first
        let tapScriptSig = try hashesForSig.filter { $0.leafHash != nil }
            .map { hash, leafHash in
                let signature = try Crypto.signSchnorr(hash, with: pk)
                return TapScriptSig(pubKey: toXOnly(pk.publicKey().data), signature: signature, leafHash: leafHash!)
            }
        if let tapKeySig {
            inputs[index].update(key: \.tapKeySig, value: tapKeySig)
        }
        if !tapScriptSig.isEmpty {
            inputs[index].update(key: \.tapScriptSig, value: tapScriptSig)
        }
    }

    public func finalizeAllInputs() throws {
        for i in 0..<inputs.count {
            try finalizeInput(index: i)
        }
    }

    public func finalizeInput(index: Int) throws {
        guard inputs.indices.contains(index), tx.inputs.indices.contains(index) else {
            throw PsbtError.indexOutOfBounds
        }
        if inputs[index].isTaprootInput {
            try _finalizeTaprootInput(index: index)
        } else {
            try _finalizeInput(index: index)
        }
    }

    private func _finalizeInput(index: Int) throws {
        let (finalScriptSig, finalScriptWitness) = try prepareFinalScripts(input: inputs[index], index: index)
        if let finalScriptSig {
            inputs[index].update(key: \.finalScriptSig, value: finalScriptSig)
        }
        if let finalScriptWitness {
            inputs[index].update(key: \.finalScriptWitness, value: finalScriptWitness)
        }
        inputs[index].clearFinalizedInput()
    }

    private func _finalizeTaprootInput(index: Int, tapLeafHashToFinalize: Data? = nil) throws {
        if inputs[index].witnessUtxo == nil {
            throw PsbtError.utxoInputItemRequired
        }
        if let tapKeySig = inputs[index].tapKeySig {
            let finalScriptWitness = witnessStackToScriptWitness(witness: P2tr.witnessFromSignature(tapKeySig))
            inputs[index].update(key: \.finalScriptWitness, value: finalScriptWitness)
        } else {
            let finalScriptWitness = try inputs[index].finalizeTapScript(with: tapLeafHashToFinalize)
            inputs[index].update(key: \.finalScriptWitness, value: finalScriptWitness)
        }

        inputs[index].clearFinalizedInput()
    }

    private func getHashForSig(index: Int, sigHashTypes: [BTCSighashType]) throws -> (hash: Data, sighashType: BTCSighashType) {
        let input = inputs[index]
        let sigHashType = (input.sighashType != nil) ? BTCSighashType(rawValue: input.sighashType!) : BTCSighashType.ALL
        try checkSighashTypeAllowed(sigHashType: sigHashType, sigHashTypes: sigHashTypes)

        let prevOut: TransactionOutput

        if let witnessUtxo = inputs[index].witnessUtxo {
            prevOut = witnessUtxo
        } else if let nonWitnessUtxo = inputs[index].nonWitnessUtxo {
            prevOut = try previousOutput(for: index, in: nonWitnessUtxo)
        } else {
            throw PsbtError.utxoInputItemRequired
        }

        let isP2SH = isP2SHScript(prevOut.lockingScript)
        let isP2SHP2WSH = isP2SH && input.redeemScript != nil && isP2WSHScript(input.redeemScript!)
        let isP2WSH = isP2WSHScript(prevOut.lockingScript)

        if isP2SH && input.redeemScript == nil {
            throw PsbtError.p2shMissingRedeemScript
        }
        if (isP2WSH || isP2SHP2WSH) && input.witnessScript == nil {
            throw PsbtError.p2wshMissingWitnessScript
        }

        let meaningfulScript: Data = if isP2SHP2WSH {
            input.witnessScript!
        } else if isP2WSH {
            input.witnessScript!
        } else if isP2SH {
            input.redeemScript!
        } else {
            prevOut.lockingScript
        }

        let hash: Data
        if isP2SHP2WSH || isP2WSH {
            hash = tx.hashForWitnessV0(index: index, prevOutScript: meaningfulScript, value: prevOut.value, hashType: sigHashType)
        } else if isP2WPKH(meaningfulScript) {
            let signingScript = P2pkh.init(hash: meaningfulScript[2...]).output
            hash = tx.hashForWitnessV0(index: index, prevOutScript: signingScript, value: prevOut.value, hashType: sigHashType)
        } else {
            hash = tx.hashForSignature(index: index, prevOutScript: meaningfulScript, hashType: sigHashType)
        }
        return (hash, sigHashType)
    }

    private func prepareFinalScripts(input: PsbtInputUpdate, index: Int) throws -> (Data?, Data?) {
        let isP2SH = input.redeemScript != nil
        let isP2WSH = input.witnessScript != nil
        let script: Data
        if let witnessScript = input.witnessScript {
            script = witnessScript
        } else if let redeemScript = input.redeemScript {
            script = redeemScript
        } else {
            if let nonWitnessUtxo = input.nonWitnessUtxo {
                script = try previousOutput(for: index, in: nonWitnessUtxo).lockingScript
            } else if let witnessUtxo = input.witnessUtxo {
                script = witnessUtxo.lockingScript
            } else {
                script = Data()
            }
        }
        let sig = input.partialSig!
        let isSegwit = isP2WSH || isP2WPKH(script)

        let payment = try getPayment(script: script, partialSig: input.partialSig ?? [])
        let payment_input = payment.inputFromSignature(sig)
        let payment_witness = payment.witnessFromSignature(sig)

        let p2wsh = isP2WSH ? P2Wsh(redeem: payment) : nil
        let p2wsh_witness = isP2WSH ? P2Wsh.witnessFrom(redeem: payment, input: payment_input, witness: payment_witness) : nil

        let p2sh = isP2SH ? P2sh(redeem: p2wsh ?? payment) : nil
        let p2sh_input = isP2SH ? P2sh.inputFrom(redeem: p2wsh ?? payment, input: isP2WSH ? .init() : payment_input) : nil

        var finalScriptSig: Data? = nil
        var finalScriptWitness: Data? = nil

        if isSegwit {
            if isP2WSH {
                finalScriptWitness = witnessStackToScriptWitness(witness: p2wsh_witness!)
            } else {
                finalScriptWitness = witnessStackToScriptWitness(witness: payment_witness)
            }
            if isP2SH {
                finalScriptSig = p2sh_input
            }
        } else {
            if isP2SH {
                finalScriptSig = p2sh_input
            } else {
                finalScriptSig = payment_input
            }
        }
        return (finalScriptSig, finalScriptWitness)
    }

    private func getTaprootHashesForSig(inputIndex: Int, publicKey: Data, tapLeafHashToSign: Data? = nil, sigHashTypes: [BTCSighashType]? = nil) throws -> [(hash: Data, leafHash: Data?)] {
        let input = inputs[inputIndex]
        let sigHashType = (input.sighashType != nil) ? BTCSighashType(rawValue: input.sighashType!) : BTCSighashType.DEFAULT
        try checkSighashTypeAllowed(sigHashType: sigHashType, sigHashTypes: sigHashTypes)

        let prevOuts = try inputs.map { try getScriptAndAmountFromUtxo(input: $0, index: inputIndex) }
        let signingScripts = prevOuts.map(\.script)
        let values = prevOuts.map(\.value)

        var hashes = [(hash: Data, leafHash: Data?)]()

        if input.tapInternalKey != nil && tapLeafHashToSign == nil {
            let script = signingScripts[inputIndex]
            let outputKey = isP2TR(script) ? script[2..<34] : Data()
            if toXOnly(publicKey) == outputKey {
                let tapKeyHash = tx.hashForWitnessV1(index: inputIndex, prevOutScripts: signingScripts, values: values, hashType: sigHashType)
                hashes.append((tapKeyHash, nil))
            }
        }

        let tapLeafHashes = input.tapLeafScript?
            .filter { pubkeyInScript(pubkey: publicKey, script: $0.script) }
            .map(\.leafHash)
            .filter { tapLeafHashToSign == nil || tapLeafHashToSign == $0 }
            .map { leafHash in
                let tapScriptHash = tx.hashForWitnessV1(index: inputIndex, prevOutScripts: signingScripts, values: values, hashType: BTCSighashType.DEFAULT, leafHash: leafHash)
                return (tapScriptHash, leafHash)
            }
        if let tapLeafHashes {
            hashes.append(contentsOf: tapLeafHashes)
        }

        return hashes
    }

    public func getScriptAndAmountFromUtxo(input: PsbtInputUpdate, index: Int) throws -> (script: Data, value: UInt64) {
        guard inputs.indices.contains(index), tx.inputs.indices.contains(index) else {
            throw PsbtError.indexOutOfBounds
        }
        if let witnessUtxo = input.witnessUtxo {
            return (witnessUtxo.lockingScript, witnessUtxo.value)
        } else if let nonWitnessUtxo = input.nonWitnessUtxo {
            let out = try previousOutput(for: index, in: nonWitnessUtxo)
            return (out.lockingScript, out.value)
        } else {
            throw PsbtError.utxoInputItemRequired
        }
    }

    func validateNonWitnessUtxoOutputIndexes() throws {
        for (index, input) in inputs.enumerated() {
            guard let nonWitnessUtxo = input.nonWitnessUtxo else { continue }
            _ = try previousOutput(for: index, in: nonWitnessUtxo)
        }
    }

    private func previousOutput(for inputIndex: Int, in nonWitnessUtxo: Data) throws -> TransactionOutput {
        guard inputs.indices.contains(inputIndex), tx.inputs.indices.contains(inputIndex) else {
            throw PsbtError.indexOutOfBounds
        }
        let previousTransaction = try Transaction.deserializeChecked(nonWitnessUtxo)
        let previousOutputIndex = tx.inputs[inputIndex].previousOutput.index
        guard let outputIndex = Int(exactly: previousOutputIndex),
              previousTransaction.outputs.indices.contains(outputIndex) else {
            throw PsbtError.indexOutOfBounds
        }
        return previousTransaction.outputs[outputIndex]
    }

    private func checkSighashTypeAllowed(sigHashType: BTCSighashType, sigHashTypes: [BTCSighashType]?) throws {
        if let sigHashTypes, !sigHashTypes.map(\.rawValue).contains(sigHashType.rawValue) {
            throw PsbtError.sigHashTypeMissMatch
        }
    }

    /// Extracts the transaction from the Partially Signed Bitcoin Transaction (PSBT).
    /// This method replaces the signature script and witness data of each input with the final script signature and witness.
    /// - Returns: The extracted transaction.
    public func extractTransaction() -> Transaction {
        let tx = self.tx
        inputs.enumerated().forEach { offset, element in
            if let finalScriptSig = element.finalScriptSig {
                tx.inputs[offset].signatureScript = finalScriptSig
            }
            if let finalScriptWitness = element.finalScriptWitness {
                tx.inputs[offset].witness = scriptWitnessToWitnessStack(witness: finalScriptWitness)
            }
        }
        return tx
    }

    public var fee: UInt64 {
        (try? calculateFee()) ?? 0
    }

    public func calculateFee() throws -> UInt64 {
        var inputAmount: UInt64 = 0
        for (idx, update) in inputs.enumerated() {
            if let witnessUtxo = update.witnessUtxo {
                let (sum, overflow) = inputAmount.addingReportingOverflow(witnessUtxo.value)
                guard !overflow else { throw PsbtError.invalidTransactionAmounts }
                inputAmount = sum
            } else if let nonWitnessUtxo = update.nonWitnessUtxo {
                let output = try previousOutput(for: idx, in: nonWitnessUtxo)
                let (sum, overflow) = inputAmount.addingReportingOverflow(output.value)
                guard !overflow else { throw PsbtError.invalidTransactionAmounts }
                inputAmount = sum
            }
        }
        var outputAmount: UInt64 = 0
        for output in tx.outputs {
            let (sum, overflow) = outputAmount.addingReportingOverflow(output.value)
            guard !overflow else { throw PsbtError.invalidTransactionAmounts }
            outputAmount = sum
        }
        guard inputAmount >= outputAmount else { throw PsbtError.invalidTransactionAmounts }
        return inputAmount - outputAmount
    }
}

func getPayment(script: Data, partialSig: [PartialSig]) throws -> WitnessPaymentType {
    if isP2MS(script) {
        return try P2MS(output: script)
    } else if isP2PK(script) {
        return try P2pk(output: script)
    } else if isP2PKH(script) {
        return try P2pkh(output: script)
    } else if isP2WPKH(script) {
        return try P2wpkh(output: script)
    } else {
        throw PsbtError.cannotFinalize
    }
}

func pubkeyInScript(pubkey: Data, script: Data) -> Bool {
    pubkeyPositionInScript(pubkey: pubkey, script: script) >= 0
}

func pubkeyPositionInScript(pubkey: Data, script: Data) -> Int {
    let pubkeyHash = _Hash.ripemd160(pubkey)
    let pubkeyXonly = pubkey.xOnly
    let chunks = Script(data: script)?.scriptChunks
    let index = chunks?.compactMap({ $0 as? DataChunk }).firstIndex(where: { chunk in
        chunk.pushedData == pubkey || chunk.pushedData == pubkeyHash || chunk.pushedData == pubkeyXonly
    })
    return index ?? -1
}

/// p2pkh input <==> [signature, pubkey] ,  witness: input ==> [empty]
///
/// p2pk input <==> signature, witness: input ==> [empty]
///
/// p2wpkh witness <==> [signature, pubkey] ,  input: witness ==> [empty]
///
/// p2tr witness <==> [signature],  witness ==> redeem
///
/// p2sh redeem.witness ==> witness , redeem <==> input, redeem ==> hash
///
/// p2wsh redeem <==> witness, input ==> [empty
