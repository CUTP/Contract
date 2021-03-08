/* eslint-disable no-unused-expressions */
const console = require( 'tracer' ).colorConsole()
const { expect } = require( 'chai' )
const { bsv, buildContractClass, signTx, toHex, getPreimage, Sig, Int, PubKey, Ripemd160, SigHashPreimage, num2bin, bin2num, Bytes, serializeState, STATE_LEN_2BYTES, deserializeState } = require( 'scryptlib' )
const {
  string2Hex, loadTokenContractDesc, compileContract, TokenValueLen,
  CONTRACT_BRFC_ID,
  BATON_BRFC_ID,
  TOKEN_BRFC_ID,
  changTxForMSB,

  genesisSchema,
  batonSchema,
  tokenSchema

} = require( '../helper' )

const Signature = bsv.crypto.Signature
const BN = bsv.crypto.BN
const Interpreter = bsv.Script.Interpreter

const inputIndex = 0
const inputSatoshis = 546
const minFee = 546
const dummyTxId = 'a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458'
const reversedDummyTxId = '5884e5db9de218238671572340b207ee85b628074e7e467096c267266baf77a4'

const utxo = {
  txId: dummyTxId,
  outputIndex: 0,
  script: '', // placeholder
  satoshis: inputSatoshis
}
const tx = new bsv.Transaction().from( utxo )

const outputAmount = 222222

import { witness0, witness1, witness2, getWitnessByPubKey } from './auth.mock'

describe( 'Controlled UTXO Token', () => {
  let Genesis, Baton, Token, privateKey1, publicKey1, privateKey2, publicKey2

  before( () => {
    Genesis = buildContractClass( loadTokenContractDesc( 'Genesis_desc.json' ) )
    Baton = buildContractClass( loadTokenContractDesc( 'Baton_desc.json' ) )
    Token = buildContractClass( loadTokenContractDesc( 'Token_desc.json' ) )
    // Token = buildContractClass( compileContract( 'FungibleTokenUtxo.scrypt' ) )
    // console.log( Token )

    privateKey1 = bsv.PrivateKey.fromRandom( 'testnet' )
    publicKey1 = bsv.PublicKey.fromPrivateKey( privateKey1 )
    privateKey2 = bsv.PrivateKey.fromRandom( 'testnet' )
    publicKey2 = bsv.PublicKey.fromPrivateKey( privateKey2 )
  } )

  it( 'Transfer 1-2', () => {
    const sighashType = Signature.SIGHASH_ANYONECANPAY | Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID

    const ownerPrivKey = privateKey1
    const ownerAddress = privateKey1.toAddress()
    const ownerPubKey = publicKey1
    const ownerPKH = bsv.crypto.Hash.sha256ripemd160( ownerPubKey.toBuffer() )

    const maxSupply = new BN( 0 )
    const witnessAddress = publicKey1.toAddress()
    const contractId = dummyTxId
    const prevOutpoint = reversedDummyTxId + '00000000'
    const holderSatoshi = 546
    const NOTIFY_SATOSHI = 546
    const toAddress = privateKey2.toAddress()
    const changeAddress = privateKey1.toAddress()

    const token = new Token(
      new Bytes(contractId),
      [
        BigInt(0),
        witness0.pubKey,
        witness1.pubKey,
        witness2.pubKey
      ],
      25 )

    console.log(token.asmVars)
    const asmVars = token.asmVars
    const witnessList = [
      bin2num(asmVars['witnesses[0]']),
      bin2num(asmVars['witnesses[1]']),
      bin2num(asmVars['witnesses[2]']),
      bin2num(asmVars['witnesses[3]'])
    ]

    const ownerSupply = 1000

    // codePart + OP_RETURN tokenAmount(32bytes) authCount(1byte) ownerPkh(20bytes) TOKEN_BRFC_ID
    const tokenData = serializeState({
      amount: num2bin(ownerSupply, TokenValueLen),
      authCount: 0,
      holderPKH: toHex(ownerAddress.hashBuffer),
      brfc: TOKEN_BRFC_ID
    }, STATE_LEN_2BYTES, tokenSchema)

    token.setDataPart(tokenData)

    console.log( token )

    console.log( token.lockingScript.toASM() )
    console.log( token.lockingScript.toHex() )

    console.log( token.codePart.toASM() )
    console.log( token.dataPart.toASM() )

    // make a copy since it will be mutated
    const tx0 = bsv.Transaction.shallowCopy( tx )

    // code part
    const lockingBodyScript = token.codePart.toASM()

    // 非标输出，0
    // 创建 UTXO Token LockingScript
    // prevOutpoint(36bytes) + ownerPkh(20bytes) + tokenAmount(32bytes) = 126bytes(7e)
    const newTokenAuthCount = 0
    const newTokenSupply = 700

    // codePart + OP_RETURN tokenAmount(32bytes)+count(1byte)  ownerPkh(20bytes) TOKEN_BRFC_ID
    const newTokenData = serializeState({
      amount: num2bin(newTokenSupply, TokenValueLen),
      authCount: newTokenAuthCount,
      holderPKH: toHex(toAddress.hashBuffer),
      brfc: TOKEN_BRFC_ID
    }, STATE_LEN_2BYTES, tokenSchema)

    const newTokenLockingScript = lockingBodyScript + ' ' + newTokenData
    const newTokenScript = bsv.Script.fromASM( newTokenLockingScript )

    tx0.addOutput( new bsv.Transaction.Output( {
      script: newTokenScript,
      satoshis: holderSatoshi
    } ) )

    const changeTokenAuthCount = 0
    const changeTokenSupply = 300

    // codePart + OP_RETURN tokenAmount(32bytes) count(1byte)  ownerPkh(20bytes) TOKEN_BRFC_ID
    const changeTokenData = serializeState({
      amount: num2bin(changeTokenSupply, TokenValueLen),
      authCount: changeTokenAuthCount,
      holderPKH: toHex(changeAddress.hashBuffer),
      brfc: TOKEN_BRFC_ID
    }, STATE_LEN_2BYTES, tokenSchema)

    const changeTokenLockingScript = lockingBodyScript + ' ' + changeTokenData
    console.log(changeTokenLockingScript)
    const changeTokenScript = bsv.Script.fromASM( changeTokenLockingScript )

    tx0.addOutput( new bsv.Transaction.Output( {
      script: changeTokenScript,
      satoshis: holderSatoshi
    } ) )

    tx0.addOutput( new bsv.Transaction.Output( {
      script: bsv.Script.buildPublicKeyHashOut( toAddress ),
      satoshis: NOTIFY_SATOSHI
    } ) )

    const prevLockingScript = token.lockingScript.toASM()

    const preimage = getPreimage( tx0, prevLockingScript, inputSatoshis, 0, sighashType )
    console.log( preimage.outpoint )

    const rabinSigs = [ ]
    const paddingBytes = [ ]

    for (const pubKey of witnessList) {
      const witness = getWitnessByPubKey(pubKey)
      console.log(pubKey, witness)
      if (witness) {
        const sig = witness.authIssue( { outpoint: preimage.outpoint.hex } )
        rabinSigs.push(new Int(sig.signature))
        paddingBytes.push(new Bytes(sig.paddingBytes))
      } else {
        rabinSigs.push(new Int(0))
        paddingBytes.push(new Bytes(''))
      }
    }

    const sig = signTx( tx0, ownerPrivKey, prevLockingScript, inputSatoshis, 0, sighashType )

    const transferFn = token.transfer( new Sig( toHex( sig ) ), new PubKey( toHex( ownerPubKey ) ), new Ripemd160( toHex( toAddress.hashBuffer ) ), new Int( newTokenSupply ), new Ripemd160( toHex( changeAddress.hashBuffer ) ), new Int( changeTokenSupply ), NOTIFY_SATOSHI, holderSatoshi, new Bytes(''), preimage, rabinSigs, paddingBytes )

    const unlockingScript = transferFn.toScript()

    console.log( `TransferUnlockingScriptSize=${unlockingScript.toBuffer().length}` )

    tx0.inputs[ 0 ].output = new bsv.Transaction.Output( {
      script: bsv.Script.fromASM( prevLockingScript ),
      satoshis: inputSatoshis
    } )
    tx0.inputs[ 0 ].setScript( unlockingScript )

    console.log( tx0 )

    // 计算所需的费用
    // 所有输出的satoshis之和，所有输入的satoshi之和，判断交易的大小
    console.log( 'Pre-Transaction Size', tx0._estimateFee() )
    // 根据txSize计算所需的手续费
    // feePerKb = 500
    tx0.feePerKb(500)
    console.log('Tx getFee', tx0.getFee(), tx0._estimateFee())
    const needFee = tx0._estimateFee() - tx0.getFee()
    console.log('Tx Fee', needFee)
    // 准备一个所需的费用输出
    tx0.addInput(
      new bsv.Transaction.Input({
        prevTxId: dummyTxId,
        outputIndex: 1,
        script: ''
      }),
      bsv.Script.fromASM('OP_DUP OP_HASH160 05a24d44e37cae0f4e231514c3ad512d313b1416 OP_EQUALVERIFY OP_CHECKSIG'),
      needFee
    )
    console.log('Tx result getFee', tx0.getFee(), tx0._estimateFee())

    const context = { tx: tx0, inputIndex, inputSatoshis }
    // console.log( `"hex": "${tx0.serialize()}"`, inputIndex, inputSatoshis )
    const result = transferFn.verify( context )

    console.log( `TransferUnlockingScriptSize=${unlockingScript.toBuffer().length}` )
    console.log( 'Token Size', token.lockingScript.toHex().length / 2 )
    console.log( 'Transaction Size', tx0.serialize().length / 2 )

    // console.log( result )
    expect( result.success, result.error ).to.be.true
  } )

  it( 'Transfer 1-1', () => {
    const sighashType = Signature.SIGHASH_ANYONECANPAY | Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID

    const ownerPrivKey = privateKey1
    const ownerAddress = privateKey1.toAddress()
    const ownerPubKey = publicKey1
    const ownerPKH = bsv.crypto.Hash.sha256ripemd160( ownerPubKey.toBuffer() )

    const maxSupply = new BN( 0 )
    const witnessAddress = publicKey1.toAddress()
    const contractId = dummyTxId
    const prevOutpoint = reversedDummyTxId + '00000000'
    const holderSatoshi = 546
    const NOTIFY_SATOSHI = 546
    const toAddress = privateKey2.toAddress()
    const changeAddress = privateKey1.toAddress()

    const token = new Token(
      new Bytes(contractId),
      [
        BigInt(0),
        witness0.pubKey,
        witness1.pubKey,
        witness2.pubKey
      ],
      25 )

    console.log(token.asmVars)
    const asmVars = token.asmVars
    const witnessList = [
      bin2num(asmVars['witnesses[0]']),
      bin2num(asmVars['witnesses[1]']),
      bin2num(asmVars['witnesses[2]']),
      bin2num(asmVars['witnesses[3]'])
    ]

    const ownerSupply = 1000

    // codePart + OP_RETURN tokenAmount(32bytes)+authCount(1byte) ownerPkh(20bytes) TOKEN_BRFC_ID
    const tokenData = serializeState({
      amount: num2bin(ownerSupply, TokenValueLen),
      authCount: 0,
      holderPKH: toHex(ownerAddress.hashBuffer),
      brfc: TOKEN_BRFC_ID
    }, STATE_LEN_2BYTES, tokenSchema)

    token.setDataPart(tokenData)
    console.log( token )

    console.log( token.lockingScript.toASM() )
    console.log( token.lockingScript.toHex() )

    console.log( token.codePart.toASM() )
    console.log( token.dataPart.toASM() )

    // make a copy since it will be mutated
    const tx0 = bsv.Transaction.shallowCopy( tx )

    // code part
    const lockingBodyScript = token.codePart.toASM()

    // 非标输出，0
    // 创建 UTXO Token LockingScript
    const newTokenAuthCount = 0
    const newTokenSupply = 1000

    // codePart + OP_RETURN tokenAmount(32bytes)+count(1byte)  ownerPkh(20bytes) TOKEN_BRFC_ID
    const newTokenData = serializeState({
      amount: num2bin(newTokenSupply, TokenValueLen),
      authCount: newTokenAuthCount,
      holderPKH: toHex(toAddress.hashBuffer),
      brfc: TOKEN_BRFC_ID
    }, STATE_LEN_2BYTES, tokenSchema)
    const newTokenLockingScript = lockingBodyScript + ' ' + newTokenData
    const newTokenScript = bsv.Script.fromASM( newTokenLockingScript )

    tx0.addOutput( new bsv.Transaction.Output( {
      script: newTokenScript,
      satoshis: holderSatoshi
    } ) )

    const changeTokenAuthCount = 0
    const changeTokenSupply = 0

    // 添加通知, 通知用户
    tx0.addOutput( new bsv.Transaction.Output( {
      script: bsv.Script.buildPublicKeyHashOut( toAddress ),
      satoshis: NOTIFY_SATOSHI
    } ) )

    const prevLockingScript = token.lockingScript.toASM()

    changTxForMSB( tx0, prevLockingScript, inputSatoshis, 0, sighashType )

    const preimage = getPreimage( tx0, prevLockingScript, inputSatoshis, 0, sighashType )
    console.log( preimage.outpoint )
    const rabinSigs = [ ]
    const paddingBytes = [ ]

    for (const pubKey of witnessList) {
      const witness = getWitnessByPubKey(pubKey)
      console.log(pubKey, witness)
      if (witness) {
        const sig = witness.authIssue( { outpoint: preimage.outpoint.hex } )
        rabinSigs.push(new Int(sig.signature))
        paddingBytes.push(new Bytes(sig.paddingBytes))
      } else {
        rabinSigs.push(new Int(0))
        paddingBytes.push(new Bytes(''))
      }
    }

    const sig = signTx( tx0, ownerPrivKey, prevLockingScript, inputSatoshis, 0, sighashType )

    const prevOutput = ''

    const transferFn = token.transfer( new Sig( toHex( sig ) ), new PubKey( toHex( ownerPubKey ) ), new Ripemd160( toHex( toAddress.hashBuffer ) ), new Int( newTokenSupply ), new Ripemd160( toHex( changeAddress.hashBuffer ) ), new Int( changeTokenSupply ), NOTIFY_SATOSHI, holderSatoshi, new Bytes(prevOutput), preimage, rabinSigs, paddingBytes )

    const unlockingScript = transferFn.toScript()

    console.log( `TransferUnlockingScriptSize=${unlockingScript.toBuffer().length}` )

    tx0.inputs[ 0 ].output = new bsv.Transaction.Output( {
      script: bsv.Script.fromASM( prevLockingScript ),
      satoshis: inputSatoshis
    } )
    tx0.inputs[ 0 ].setScript( unlockingScript )

    console.log( tx0 )
    // 计算所需的费用
    // 所有输出的satoshis之和，所有输入的satoshi之和，判断交易的大小
    console.log( 'Pre-Transaction Size', tx0._estimateFee() )
    // 根据txSize计算所需的手续费
    // feePerKb = 500
    tx0.feePerKb(500)
    console.log('Tx getFee', tx0.getFee(), tx0._estimateFee())
    const needFee = tx0._estimateFee() - tx0.getFee()
    console.log('Tx Fee', needFee)
    // 准备一个所需的费用输出
    tx0.addInput(
      new bsv.Transaction.Input({
        prevTxId: dummyTxId,
        outputIndex: 1,
        script: ''
      }),
      bsv.Script.fromASM('OP_DUP OP_HASH160 05a24d44e37cae0f4e231514c3ad512d313b1416 OP_EQUALVERIFY OP_CHECKSIG'),
      needFee
    )
    console.log('Tx result getFee', tx0.getFee(), tx0._estimateFee())
    const context = { tx: tx0, inputIndex, inputSatoshis }
    // console.log( `"hex": "${tx0.serialize()}"`, inputIndex, inputSatoshis )
    const result = transferFn.verify( context )

    console.log( `TransferUnlockingScriptSize=${unlockingScript.toBuffer().length}` )
    console.log( 'Token Size', token.lockingScript.toHex().length / 2 )
    console.log( 'Transaction Size', tx0.serialize().length / 2 )

    // console.log( result )
    expect( result.success, result.error ).to.be.true
  } )

  it( 'change satoshi is zero, 1-1', () => {
    const sighashType = Signature.SIGHASH_ANYONECANPAY | Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID

    const ownerPrivKey = privateKey1
    const ownerAddress = privateKey1.toAddress()
    const ownerPubKey = publicKey1
    const ownerPKH = bsv.crypto.Hash.sha256ripemd160( ownerPubKey.toBuffer() )

    const maxSupply = new BN( 0 )
    const witnessAddress = publicKey1.toAddress()
    const contractId = dummyTxId
    const prevOutpoint = reversedDummyTxId + '00000000'
    const holderSatoshi = 546
    const NOTIFY_SATOSHI = 546
    const toAddress = privateKey2.toAddress()
    const changeAddress = privateKey1.toAddress()

    const token = new Token(
      new Bytes(contractId),
      [
        BigInt(0),
        witness0.pubKey,
        witness1.pubKey,
        witness2.pubKey
      ],
      25 )

    console.log(token.asmVars)
    const asmVars = token.asmVars
    const witnessList = [
      bin2num(asmVars['witnesses[0]']),
      bin2num(asmVars['witnesses[1]']),
      bin2num(asmVars['witnesses[2]']),
      bin2num(asmVars['witnesses[3]'])
    ]

    const ownerSupply = 1000

    // codePart + OP_RETURN tokenAmount(32bytes)+authCount(1byte) ownerPkh(20bytes) TOKEN_BRFC_ID
    const tokenData = serializeState({
      amount: num2bin(ownerSupply, TokenValueLen),
      authCount: 0,
      holderPKH: toHex(ownerAddress.hashBuffer),
      brfc: TOKEN_BRFC_ID
    }, STATE_LEN_2BYTES, tokenSchema)

    token.setDataPart(tokenData)

    console.log( token.lockingScript.toASM() )
    console.log( token.lockingScript.toHex() )

    console.log( token.codePart.toASM() )
    console.log( token.dataPart.toASM() )

    // make a copy since it will be mutated
    const tx0 = bsv.Transaction.shallowCopy( tx )

    // code part
    const lockingBodyScript = token.codePart.toASM()

    // 非标输出，0
    // 创建 UTXO Token LockingScript
    // codePart + OP_RETURN + TOKEN_BRFC_ID(6bytes) + contractId(32bytes) + prevOutpoint(36bytes) + ownerPkh(20bytes) + tokenAmount(32bytes) = 126bytes(7e)
    const newTokenAuthCount = 0
    const newTokenSupply = 1000

    // codePart + OP_RETURN tokenAmount(32bytes)+count(1byte)  ownerPkh(20bytes) TOKEN_BRFC_ID
    const newTokenData = serializeState({
      amount: num2bin(newTokenSupply, TokenValueLen),
      authCount: newTokenAuthCount,
      holderPKH: toHex(toAddress.hashBuffer),
      brfc: TOKEN_BRFC_ID
    }, STATE_LEN_2BYTES, tokenSchema)

    const newTokenLockingScript = lockingBodyScript + ' ' + newTokenData
    const newTokenScript = bsv.Script.fromASM( newTokenLockingScript )

    tx0.addOutput( new bsv.Transaction.Output( {
      script: newTokenScript,
      satoshis: holderSatoshi
    } ) )

    const changeTokenAuthCount = 0
    const changeTokenSupply = 0

    // 添加通知, 通知用户
    tx0.addOutput( new bsv.Transaction.Output( {
      script: bsv.Script.buildPublicKeyHashOut( toAddress ),
      satoshis: NOTIFY_SATOSHI
    } ) )

    const prevLockingScript = token.lockingScript.toASM()

    const preimage = getPreimage( tx0, prevLockingScript, inputSatoshis, 0, sighashType )
    console.log( preimage.outpoint )
    const rabinSigs = [ ]
    const paddingBytes = [ ]

    for (const pubKey of witnessList) {
      const witness = getWitnessByPubKey(pubKey)
      console.log(pubKey, witness)
      if (witness) {
        const sig = witness.authIssue( { outpoint: preimage.outpoint.hex } )
        rabinSigs.push(new Int(sig.signature))
        paddingBytes.push(new Bytes(sig.paddingBytes))
      } else {
        rabinSigs.push(new Int(0))
        paddingBytes.push(new Bytes(''))
      }
    }

    const sig = signTx( tx0, ownerPrivKey, prevLockingScript, inputSatoshis, 0, sighashType )
    const prevOutput = ''

    const transferFn = token.transfer( new Sig( toHex( sig ) ), new PubKey( toHex( ownerPubKey ) ), new Ripemd160( toHex( toAddress.hashBuffer ) ), new Int( newTokenSupply ), new Ripemd160( toHex( changeAddress.hashBuffer ) ), new Int( changeTokenSupply ), NOTIFY_SATOSHI, holderSatoshi, new Bytes(prevOutput), preimage, rabinSigs, paddingBytes )

    const unlockingScript = transferFn.toScript()

    console.log( `TransferUnlockingScriptSize=${unlockingScript.toBuffer().length}` )

    tx0.inputs[ 0 ].output = new bsv.Transaction.Output( {
      script: bsv.Script.fromASM( prevLockingScript ),
      satoshis: inputSatoshis
    } )
    tx0.inputs[ 0 ].setScript( unlockingScript )

    console.log( tx0 )
    // 计算所需的费用
    // 所有输出的satoshis之和，所有输入的satoshi之和，判断交易的大小
    console.log( 'Pre-Transaction Size', tx0._estimateFee() )
    // 根据txSize计算所需的手续费
    // feePerKb = 500
    tx0.feePerKb(500)
    console.log('Tx getFee', tx0.getFee(), tx0._estimateFee())
    const needFee = tx0._estimateFee() - tx0.getFee()
    console.log('Tx Fee', needFee)
    // 准备一个所需的费用输出
    tx0.addInput(
      new bsv.Transaction.Input({
        prevTxId: dummyTxId,
        outputIndex: 1,
        script: ''
      }),
      bsv.Script.fromASM('OP_DUP OP_HASH160 05a24d44e37cae0f4e231514c3ad512d313b1416 OP_EQUALVERIFY OP_CHECKSIG'),
      needFee
    )
    console.log('Tx result getFee', tx0.getFee(), tx0._estimateFee())
    const context = { tx: tx0, inputIndex, inputSatoshis }
    // console.log( `"hex": "${tx0.serialize()}"`, inputIndex, inputSatoshis )
    const result = transferFn.verify( context )

    console.log( `TransferUnlockingScriptSize=${unlockingScript.toBuffer().length}` )
    console.log( 'Token Size', token.lockingScript.toHex().length / 2 )
    console.log( 'Transaction Size', tx0.serialize().length / 2 )

    // console.log( result )
    expect( result.success, result.error ).to.be.true
  } )

  it( 'Transfer 1 to 2 With preOutput', () => {
    const sighashType = Signature.SIGHASH_ANYONECANPAY | Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID

    const ownerPrivKey = privateKey1
    const ownerAddress = privateKey1.toAddress()
    const ownerPubKey = publicKey1
    const ownerPKH = bsv.crypto.Hash.sha256ripemd160( ownerPubKey.toBuffer() )

    const maxSupply = new BN( 0 )
    const witnessAddress = publicKey1.toAddress()
    const contractId = dummyTxId
    const prevOutpoint = reversedDummyTxId + '00000000'
    const holderSatoshi = 546
    const NOTIFY_SATOSHI = 546
    const toAddress = privateKey2.toAddress()
    const changeAddress = privateKey1.toAddress()

    const token = new Token(
      new Bytes(contractId),
      [
        BigInt(0),
        witness0.pubKey,
        witness1.pubKey,
        witness2.pubKey
      ],
      25 )

    console.log(token.asmVars)
    const asmVars = token.asmVars
    const witnessList = [
      bin2num(asmVars['witnesses[0]']),
      bin2num(asmVars['witnesses[1]']),
      bin2num(asmVars['witnesses[2]']),
      bin2num(asmVars['witnesses[3]'])
    ]

    const ownerSupply = 1000

    // codePart + OP_RETURN tokenAmount(32bytes)+authCount(1byte) ownerPkh(20bytes) TOKEN_BRFC_ID
    const tokenData = serializeState({
      amount: num2bin(ownerSupply, TokenValueLen),
      authCount: 0,
      holderPKH: toHex(ownerAddress.hashBuffer),
      brfc: TOKEN_BRFC_ID
    }, STATE_LEN_2BYTES, tokenSchema)

    token.setDataPart(tokenData)

    console.log( token )

    console.log( token.lockingScript.toASM() )
    console.log( token.lockingScript.toHex() )

    console.log( token.codePart.toASM() )
    console.log( token.dataPart.toASM() )

    // make a copy since it will be mutated
    const tx0 = bsv.Transaction.shallowCopy( tx )

    // code part
    const lockingBodyScript = token.codePart.toASM()

    // 前输出，在所有的Token输出之前还有的输出
    const prevScript = bsv.Script.buildPublicKeyHashOut( ownerAddress )
    const prevSatoshi = 5000
    tx0.addOutput( new bsv.Transaction.Output( {
      script: prevScript,
      satoshis: prevSatoshi
    } ) )

    // 获取第一个输出的字节数组
    const prevOutput = tx0.outputs[0].toBufferWriter().toBuffer().toString('hex')
    console.log(prevOutput)

    // 非标输出，0
    // 创建 UTXO Token LockingScript

    const newTokenAuthCount = 0
    const newTokenSupply = 700

    // codePart + OP_RETURN tokenAmount(32bytes)+count(1byte)  ownerPkh(20bytes) TOKEN_BRFC_ID
    const newTokenData = serializeState({
      amount: num2bin(newTokenSupply, TokenValueLen),
      authCount: newTokenAuthCount,
      holderPKH: toHex(toAddress.hashBuffer),
      brfc: TOKEN_BRFC_ID
    }, STATE_LEN_2BYTES, tokenSchema)

    const newTokenLockingScript = lockingBodyScript + ' ' + newTokenData
    const newTokenScript = bsv.Script.fromASM( newTokenLockingScript )

    tx0.addOutput( new bsv.Transaction.Output( {
      script: newTokenScript,
      satoshis: holderSatoshi
    } ) )

    const changeTokenAuthCount = 0
    const changeTokenSupply = 300

    // codePart + OP_RETURN tokenAmount(32bytes)+count(1byte)  ownerPkh(20bytes) TOKEN_BRFC_ID
    const changeTokenData = serializeState({
      amount: num2bin(changeTokenSupply, TokenValueLen),
      authCount: changeTokenAuthCount,
      holderPKH: toHex(changeAddress.hashBuffer),
      brfc: TOKEN_BRFC_ID
    }, STATE_LEN_2BYTES, tokenSchema)

    const changeTokenLockingScript = lockingBodyScript + ' ' + changeTokenData
    console.log(changeTokenLockingScript)
    const changeTokenScript = bsv.Script.fromASM( changeTokenLockingScript )

    tx0.addOutput( new bsv.Transaction.Output( {
      script: changeTokenScript,
      satoshis: holderSatoshi
    } ) )

    // 添加通知, 通知用户
    tx0.addOutput( new bsv.Transaction.Output( {
      script: bsv.Script.buildPublicKeyHashOut( toAddress ),
      satoshis: NOTIFY_SATOSHI
    } ) )

    const prevLockingScript = token.lockingScript.toASM()

    const preimage = getPreimage( tx0, prevLockingScript, inputSatoshis, 0, sighashType )
    console.log( preimage.outpoint )
    const rabinSigs = [ ]
    const paddingBytes = [ ]

    for (const pubKey of witnessList) {
      const witness = getWitnessByPubKey(pubKey)
      console.log(pubKey, witness)
      if (witness) {
        const sig = witness.authIssue( { outpoint: preimage.outpoint.hex } )
        rabinSigs.push(new Int(sig.signature))
        paddingBytes.push(new Bytes(sig.paddingBytes))
      } else {
        rabinSigs.push(new Int(0))
        paddingBytes.push(new Bytes(''))
      }
    }

    // 构造发行商签名，只有签名同创世交易的发行商公钥一致才可以首次发行
    const sig = signTx( tx0, ownerPrivKey, prevLockingScript, inputSatoshis, 0, sighashType )

    const transferFn = token.transfer( new Sig( toHex( sig ) ), new PubKey( toHex( ownerPubKey ) ), new Ripemd160( toHex( toAddress.hashBuffer ) ), new Int( newTokenSupply ), new Ripemd160( toHex( changeAddress.hashBuffer ) ), new Int( changeTokenSupply ), NOTIFY_SATOSHI, holderSatoshi, new Bytes(prevOutput), preimage, rabinSigs, paddingBytes )

    const unlockingScript = transferFn.toScript()

    console.log( `TransferUnlockingScriptSize=${unlockingScript.toBuffer().length}` )

    tx0.inputs[ 0 ].output = new bsv.Transaction.Output( {
      script: bsv.Script.fromASM( prevLockingScript ),
      satoshis: inputSatoshis
    } )
    tx0.inputs[ 0 ].setScript( unlockingScript )

    console.log( tx0 )
    // 计算所需的费用
    // 所有输出的satoshis之和，所有输入的satoshi之和，判断交易的大小
    console.log( 'Pre-Transaction Size', tx0._estimateFee() )
    // 根据txSize计算所需的手续费
    // feePerKb = 500
    tx0.feePerKb(500)
    console.log('Tx getFee', tx0.getFee(), tx0._estimateFee())
    const needFee = tx0._estimateFee() - tx0.getFee()
    console.log('Tx Fee', needFee)
    // 准备一个所需的费用输出
    tx0.addInput(
      new bsv.Transaction.Input({
        prevTxId: dummyTxId,
        outputIndex: 1,
        script: ''
      }),
      bsv.Script.fromASM('OP_DUP OP_HASH160 05a24d44e37cae0f4e231514c3ad512d313b1416 OP_EQUALVERIFY OP_CHECKSIG'),
      needFee
    )
    console.log('Tx result getFee', tx0.getFee(), tx0._estimateFee())
    const context = { tx: tx0, inputIndex, inputSatoshis }
    // console.log( `"hex": "${tx0.serialize()}"`, inputIndex, inputSatoshis )
    const result = transferFn.verify( context )

    console.log( `TransferUnlockingScriptSize=${unlockingScript.toBuffer().length}` )
    console.log( 'Token Size', token.lockingScript.toHex().length / 2 )
    console.log( 'Transaction Size', tx0.serialize().length / 2 )

    // console.log( result )
    expect( result.success, result.error ).to.be.true
  } )

  it( 'Transfer n-2', () => {
    const sighashType = Signature.SIGHASH_ANYONECANPAY | Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID

    const ownerPrivKey = privateKey1
    const ownerAddress = privateKey1.toAddress()
    const ownerPubKey = publicKey1

    const witnessAddress = publicKey1.toAddress()
    const contractId = dummyTxId
    const prevOutpoint = reversedDummyTxId + '00000000'
    const holderSatoshi = 546
    const NOTIFY_SATOSHI = 546
    const toAddress = privateKey2.toAddress()
    const changeAddress = privateKey1.toAddress()

    const token = new Token(
      new Bytes(contractId),
      [
        BigInt(0),
        witness0.pubKey,
        witness1.pubKey,
        witness2.pubKey
      ],
      25 )

    console.log(token.asmVars)
    const asmVars = token.asmVars
    const witnessList = [
      bin2num(asmVars['witnesses[0]']),
      bin2num(asmVars['witnesses[1]']),
      bin2num(asmVars['witnesses[2]']),
      bin2num(asmVars['witnesses[3]'])
    ]

    const ownerSupply = 1000

    // codePart + OP_RETURN tokenAmount(32bytes)+authCount(1byte) ownerPkh(20bytes) TOKEN_BRFC_ID
    const tokenData = serializeState({
      amount: num2bin(ownerSupply, TokenValueLen),
      authCount: 0,
      holderPKH: toHex(ownerAddress.hashBuffer),
      brfc: TOKEN_BRFC_ID
    }, STATE_LEN_2BYTES, tokenSchema)

    token.setDataPart(tokenData)

    // console.log( token.lockingScript.toASM() )
    // console.log( token.lockingScript.toHex() )

    // console.log( token.codePart.toASM() )
    // console.log( token.dataPart.toASM() )

    // code part
    const lockingBodyScript = token.codePart.toASM()

    const tokenUtxos = [
      {
        prevTxId: dummyTxId,
        outputIndex: 1
      },
      {
        prevTxId: dummyTxId,
        outputIndex: 2
      },
      {
        prevTxId: dummyTxId,
        outputIndex: 3
      },
      {
        prevTxId: dummyTxId,
        outputIndex: 4
      }
    ]

    // make a copy since it will be mutated
    // make a copy since it will be mutated
    // const tx0 = new bsv.Transaction( )
    const tx0 = new bsv.Transaction()

    const indexBase = tx0.inputs.length
    console.log(indexBase)

    tokenUtxos.forEach( ( utxo, index ) => {
      console.log(utxo)

      // codePart + OP_RETURN tokenAmount(32bytes)+count(1byte)  ownerPkh(20bytes) TOKEN_BRFC_ID
      const data = serializeState({
        amount: num2bin(ownerSupply, TokenValueLen),
        authCount: 0,
        holderPKH: toHex(ownerAddress.hashBuffer),
        brfc: TOKEN_BRFC_ID
      }, STATE_LEN_2BYTES, tokenSchema)

      const lockingScript = lockingBodyScript + ' ' + data
      tx0.addInput(new bsv.Transaction.Input({
        prevTxId: utxo.prevTxId,
        outputIndex: utxo.outputIndex,
        script: ''
      }), bsv.Script.fromASM(lockingScript), holderSatoshi)
      // 设置一个Dummy解锁Buffer
      tx0.inputs[ indexBase + index ].setScript( Buffer.alloc(3000) )
    })

    // 非标输出，0
    // 创建 UTXO Token LockingScript
    // codePart + OP_RETURN + TOKEN_BRFC_ID(6bytes) + contractId(32bytes) + prevOutpoint(36bytes) + ownerPkh(20bytes) + tokenAmount(32bytes) = 126bytes(7e)
    const newTokenAuthCount = 0
    const newTokenSupply = tokenUtxos.length * ownerSupply - 300

    // codePart + OP_RETURN tokenAmount(32bytes)+count(1byte)  ownerPkh(20bytes) TOKEN_BRFC_ID
    const newTokenData = serializeState({
      amount: num2bin(newTokenSupply, TokenValueLen),
      authCount: newTokenAuthCount,
      holderPKH: toHex(toAddress.hashBuffer),
      brfc: TOKEN_BRFC_ID
    }, STATE_LEN_2BYTES, tokenSchema)

    const newTokenLockingScript = lockingBodyScript + ' ' + newTokenData
    const newTokenScript = bsv.Script.fromASM( newTokenLockingScript )

    tx0.addOutput( new bsv.Transaction.Output( {
      script: newTokenScript,
      satoshis: holderSatoshi
    } ) )

    const changeTokenAuthCount = 0
    const changeTokenSupply = 300

    const changeTokenData = serializeState({
      amount: num2bin(changeTokenSupply, TokenValueLen),
      authCount: changeTokenAuthCount,
      holderPKH: toHex(changeAddress.hashBuffer),
      brfc: TOKEN_BRFC_ID
    }, STATE_LEN_2BYTES, tokenSchema)

    const changeTokenLockingScript = lockingBodyScript + ' ' + changeTokenData
    // console.log(changeTokenLockingScript)
    const changeTokenScript = bsv.Script.fromASM( changeTokenLockingScript )

    tx0.addOutput( new bsv.Transaction.Output( {
      script: changeTokenScript,
      satoshis: holderSatoshi
    } ) )

    // 添加通知, 通知用户
    tx0.addOutput( new bsv.Transaction.Output( {
      script: bsv.Script.buildPublicKeyHashOut( toAddress ),
      satoshis: NOTIFY_SATOSHI
    } ) )

    tokenUtxos.forEach( ( utxo, index ) => {
      // codePart + OP_RETURN tokenAmount(32bytes) count(1byte)  ownerPkh(20bytes) TOKEN_BRFC_ID
      const data = serializeState({
        amount: num2bin(ownerSupply, TokenValueLen),
        authCount: 0,
        holderPKH: toHex(ownerAddress.hashBuffer),
        brfc: TOKEN_BRFC_ID
      }, STATE_LEN_2BYTES, tokenSchema)

      const prevLockingScript = lockingBodyScript + ' ' + data

      console.log(holderSatoshi, indexBase + index, sighashType)
      const preimage = getPreimage( tx0, prevLockingScript, holderSatoshi, indexBase + index, sighashType )
      console.log( preimage.outpoint )

      const rabinSigs = [ ]
      const paddingBytes = [ ]

      for (const pubKey of witnessList) {
        const witness = getWitnessByPubKey(pubKey)
        console.log(pubKey, witness)
        if (witness) {
          const sig = witness.authIssue( { outpoint: preimage.outpoint.hex } )
          rabinSigs.push(new Int(sig.signature))
          paddingBytes.push(new Bytes(sig.paddingBytes))
        } else {
          rabinSigs.push(new Int(0))
          paddingBytes.push(new Bytes(''))
        }
      }

      // 构造发行商签名，只有签名同创世交易的发行商公钥一致才可以首次发行
      const sig = signTx( tx0, ownerPrivKey, prevLockingScript, holderSatoshi, indexBase + index, sighashType )

      const transferFn = token.transfer( new Sig( toHex( sig ) ), new PubKey( toHex( ownerPubKey ) ), new Ripemd160( toHex( toAddress.hashBuffer ) ), new Int( newTokenSupply ), new Ripemd160( toHex( changeAddress.hashBuffer ) ), new Int( changeTokenSupply ), NOTIFY_SATOSHI, holderSatoshi, new Bytes(''), preimage, rabinSigs, paddingBytes )

      const unlockingScript = transferFn.toScript()

      console.log( `TransferUnlockingScriptSize=${unlockingScript.toBuffer().length}` )

      tx0.inputs[ indexBase + index ].output = new bsv.Transaction.Output( {
        script: bsv.Script.fromASM( prevLockingScript ),
        satoshis: holderSatoshi
      } )
      tx0.inputs[ indexBase + index ].setScript( unlockingScript )

      const context = { tx: tx0, inputIndex: indexBase + index, inputSatoshis: holderSatoshi }
      // console.log( `"hex": "${tx0.serialize()}"`, inputIndex, inputSatoshis )
      const result = transferFn.verify( context )
      console.log( result )
      expect( result.success, result.error ).to.be.true
      console.log( `TransferUnlockingScriptSize=${unlockingScript.toBuffer().length}` )
      console.log( 'Token Size', token.lockingScript.toHex().length / 2 )
    })
    // console.log( 'Transaction Size', tx0.serialize().length / 2 )
    console.log( tx0 )

    tx0.feePerKb(500)
    console.log('Tx getFee', tx0.getFee(), tx0._estimateFee())
    const needFee = tx0._estimateFee() - tx0.getFee()
    console.log('Tx Fee', needFee)
    // 准备一个所需的费用输出
    tx0.addInput(
      new bsv.Transaction.Input({
        prevTxId: dummyTxId,
        outputIndex: 5,
        script: ''
      }),
      bsv.Script.fromASM('OP_DUP OP_HASH160 05a24d44e37cae0f4e231514c3ad512d313b1416 OP_EQUALVERIFY OP_CHECKSIG'),
      needFee
    )
    console.log('Tx result getFee', tx0.getFee(), tx0._estimateFee())
  } )
} )
