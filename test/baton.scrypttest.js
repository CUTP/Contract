/* eslint-disable no-unused-expressions */
const console = require( 'tracer' ).colorConsole()
const { expect } = require( 'chai' )
const { bsv, buildContractClass, signTx, toHex, getPreimage, Sig, Int, PubKey, Ripemd160, SigHashPreimage, num2bin, bin2num, Bytes, serializeState, STATE_LEN_2BYTES, deserializeState } = require( 'scryptlib' )
const {
  string2Hex, loadTokenContractDesc, compileContract, TokenValueLen,
  CONTRACT_BRFC_ID,
  BATON_BRFC_ID,
  TOKEN_BRFC_ID,

  calcChargeFee,

  GenesisSchema,
  BatonSchema,
  TokenSchema

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

  it( 'Issuer', () => {
    const issuerPrivKey = privateKey1
    const issuerAddress = privateKey1.toAddress()
    const issuerPubKey = publicKey1
    const witnessAddress = publicKey1.toAddress()
    const contractId = dummyTxId
    const prevOutpoint = reversedDummyTxId + '00000000'
    const newIssuerAddress = privateKey2.toAddress()
    const ownerAddress = privateKey2.toAddress()
    const initialSupply = 1024
    const holderSatoshi = 546
    const NOTIFY_SATOSHI = 546
    const changeAddress = privateKey2.toAddress()

    //
    const baton = new Baton(
      new Bytes(contractId),
      [
        BigInt(0),
        witness0.pubKey,
        witness1.pubKey,
        witness2.pubKey
      ])

    console.log(
      new Bytes(contractId),
      [
        BigInt(0),
        witness0.pubKey,
        witness1.pubKey,
        witness2.pubKey
      ]
    )

    console.log(baton.asmVars)
    const asmVars = baton.asmVars
    const witnessList = [
      bin2num(asmVars['witnesses[0]']),
      bin2num(asmVars['witnesses[1]']),
      bin2num(asmVars['witnesses[2]']),
      bin2num(asmVars['witnesses[3]'])
    ]

    // OPRETURN supply(32bytes) issuerPKH(20bytes) BRFC(6bytes)
    const batonData = serializeState({
      supply: num2bin(initialSupply, TokenValueLen),
      issuerPKH: toHex(issuerAddress.hashBuffer),
      brfc: BATON_BRFC_ID
    }, STATE_LEN_2BYTES, BatonSchema)

    baton.setDataPart( batonData )
    console.log( baton )

    console.log( baton.lockingScript.toASM() )
    console.log( baton.lockingScript.toHex() )

    console.log( baton.codePart.toASM() )
    console.log( baton.dataPart.toASM() )
    console.log( baton.dataPart.toHex() )

    const sighashType = Signature.SIGHASH_ANYONECANPAY | Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID
    // make a copy since it will be mutated
    const tx0 = bsv.Transaction.shallowCopy( tx )

    const newBaton = new Baton(
      new Bytes(contractId),
      [
        BigInt(0),
        witness0.pubKey,
        witness1.pubKey,
        witness2.pubKey
      ])

    console.log(newBaton.asmVars)

    const newBatonData = serializeState({
      supply: num2bin(initialSupply, TokenValueLen),
      issuerPKH: toHex(newIssuerAddress.hashBuffer),
      brfc: BATON_BRFC_ID
    }, STATE_LEN_2BYTES, BatonSchema)

    newBaton.setDataPart( newBatonData )

    const newBatonScript = newBaton.lockingScript

    tx0.addOutput( new bsv.Transaction.Output( {
      script: newBatonScript,
      satoshis: holderSatoshi
    } ) )

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

    // codePart + OP_RETURN tokenAmount(32bytes)+authCount(1byte) ownerPkh(20bytes) TOKEN_BRFC_ID
    const tokenData = serializeState({
      amount: num2bin(initialSupply, TokenValueLen),
      authCount: 0,
      holderPKH: toHex(ownerAddress.hashBuffer),
      brfc: TOKEN_BRFC_ID
    }, STATE_LEN_2BYTES, TokenSchema)

    token.setDataPart(tokenData)

    console.log( token )

    console.log( token.lockingScript.toASM() )
    console.log( token.lockingScript.toHex() )

    console.log( token.codePart.toASM() )
    console.log( token.dataPart.toASM() )

    const tokenScript = token.lockingScript

    tx0.addOutput( new bsv.Transaction.Output( {
      script: tokenScript,
      satoshis: holderSatoshi
    } ) )

    const prevLockingScript = baton.lockingScript.toASM()

    // changTxForMSB( tx0, prevLockingScript, inputSatoshis, 0, sighashType )
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

    const sig = signTx( tx0, issuerPrivKey, prevLockingScript, inputSatoshis, 0, sighashType )

    console.log(`"Sig(b'${toHex( sig )}')", "PubKey(b'${toHex( issuerPubKey )})", "SigHashPreimage(b'${toHex( preimage )}')"`)
    const issueFn = baton.issue( new Sig( toHex( sig ) ), new PubKey( toHex( issuerPubKey ) ), new SigHashPreimage( toHex( preimage ) ), rabinSigs, paddingBytes )

    const unlockingScript = issueFn.toScript()

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
    console.log( `"hex": "${tx0.serialize()}"`, inputIndex, inputSatoshis )
    const result = issueFn.verify( context )

    console.log( `InitiateUnlockingScriptSize=${unlockingScript.toBuffer().length}` )

    console.log( 'Baton Size', baton.lockingScript.toHex().length / 2 )
    console.log( 'Token Size', token.lockingScript.toHex().length / 2 )
    console.log( 'Transaction Size', tx0.serialize().length / 2 )

    console.log( result )
    expect( result.success, result.error ).to.be.true
  } )

  it( 'issuer no enough witness', () => {
    const issuerPrivKey = privateKey1
    const issuerAddress = privateKey1.toAddress()
    const issuerPubKey = publicKey1
    const witnessAddress = publicKey1.toAddress()
    const contractId = dummyTxId
    const prevOutpoint = reversedDummyTxId + '00000000'
    const newIssuerAddress = privateKey2.toAddress()
    const ownerAddress = privateKey2.toAddress()
    const initialSupply = 1024
    const holderSatoshi = 546
    const NOTIFY_SATOSHI = 546
    const changeAddress = privateKey2.toAddress()

    //
    const baton = new Baton(
      new Bytes(contractId),
      [
        BigInt(0),
        witness0.pubKey,
        witness1.pubKey,
        witness2.pubKey
      ])

    console.log(baton.asmVars)
    const asmVars = baton.asmVars
    const witnessList = [
      bin2num(asmVars['witnesses[0]']),
      bin2num(asmVars['witnesses[1]']),
      bin2num(asmVars['witnesses[2]']),
      bin2num(asmVars['witnesses[3]'])
    ]

    const batonData = [num2bin(initialSupply, TokenValueLen), toHex(issuerAddress.hashBuffer), BATON_BRFC_ID].join(' ')

    baton.setDataPart( batonData )
    console.log( baton )

    console.log( baton.lockingScript.toASM() )
    console.log( baton.lockingScript.toHex() )

    console.log( baton.codePart.toASM() )
    console.log( baton.dataPart.toASM() )

    const sighashType = Signature.SIGHASH_ANYONECANPAY | Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID
    // make a copy since it will be mutated
    const tx0 = bsv.Transaction.shallowCopy( tx )

    const newBaton = new Baton(
      new Bytes(contractId),
      [
        BigInt(0),
        witness0.pubKey,
        witness1.pubKey,
        witness2.pubKey
      ])

    console.log(newBaton.asmVars)

    const newBatonData = [num2bin(initialSupply, TokenValueLen), toHex(newIssuerAddress.hashBuffer), BATON_BRFC_ID].join(' ')

    newBaton.setDataPart( newBatonData )

    const newBatonScript = newBaton.lockingScript

    tx0.addOutput( new bsv.Transaction.Output( {
      script: newBatonScript,
      satoshis: holderSatoshi
    } ) )

    // change
    // tx0.change( changeAddress )
    // const changeSatoshi = tx1.outputs[ tx1.outputs.length - 1 ].satoshis

    // const changeSatoshi = 1000
    // tx0.addOutput( new bsv.Transaction.Output( {
    //   script: bsv.Script.buildPublicKeyHashOut( changeAddress ),
    //   satoshis: changeSatoshi
    // } ) )

    // console.log(tx1.toObject())

    const prevLockingScript = baton.lockingScript.toASM()

    // changTxForMSB( tx0, prevLockingScript, inputSatoshis, 0, sighashType )
    const preimage = getPreimage( tx0, prevLockingScript, inputSatoshis, 0, sighashType )
    console.log( preimage.outpoint )
    const sig0 = witness0.authIssue( { outpoint: preimage.outpoint.hex } )
    const sig1 = witness1.authIssue( { outpoint: preimage.outpoint.hex } )
    const sig2 = witness2.authIssue( { outpoint: preimage.outpoint.hex } )
    // const rabinSigs = [
    //   sig0.signature,
    //   sig1.signature,
    //   sig2.signature
    // ]
    // const paddingBytes = [
    //   new Bytes(sig0.paddingBytes),
    //   new Bytes(sig1.paddingBytes),
    //   new Bytes(sig2.paddingBytes)
    // ]

    const rabinSigs = [
      new Int(0),
      new Int(0),
      new Int(sig1.signature),
      new Int(0)
    ]
    const paddingBytes = [
      new Bytes(''),
      new Bytes(''),
      new Bytes(sig1.paddingBytes),
      new Bytes('')
    ]

    //
    const sig = signTx( tx0, issuerPrivKey, prevLockingScript, inputSatoshis, 0, sighashType )

    const issueFn = baton.issue( new Sig( toHex( sig ) ), new PubKey( toHex( issuerPubKey ) ), new SigHashPreimage( toHex( preimage ) ), rabinSigs, paddingBytes )

    const unlockingScript = issueFn.toScript()

    tx0.inputs[ 0 ].output = new bsv.Transaction.Output( {
      script: bsv.Script.fromASM( prevLockingScript ),
      satoshis: inputSatoshis
    } )
    tx0.inputs[ 0 ].setScript( unlockingScript )

    console.log( tx0 )


    console.log( 'Pre-Transaction Size', tx0._estimateFee() )
    // feePerKb = 500
    tx0.feePerKb(500)
    console.log('Tx getFee', tx0.getFee(), tx0._estimateFee())
    const needFee = tx0._estimateFee() - tx0.getFee()
    console.log('Tx Fee', needFee)
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
    console.log( `"hex": "${tx0.serialize()}"`, inputIndex, inputSatoshis )
    const result = issueFn.verify( context )

    console.log( `InitiateUnlockingScriptSize=${unlockingScript.toBuffer().length}` )

    console.log( 'Baton Size', baton.lockingScript.toHex().length / 2 )
    // console.log( 'Token Size', token.lockingScript.toHex().length / 2 )
    console.log( 'Transaction Size', tx0.serialize().length / 2 )

    console.log( result )
    expect( result.success, result.error ).to.be.false
  } )
} )
