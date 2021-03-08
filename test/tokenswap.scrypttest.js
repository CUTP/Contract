/* eslint-disable no-unused-expressions */
const console = require( 'tracer' ).colorConsole()
const { expect } = require( 'chai' )
const { bsv, buildContractClass, signTx, toHex, getPreimage, Sig, Int, PubKey, Ripemd160, SigHashPreimage, num2bin, bin2num, Bytes, serializeState, STATE_LEN_2BYTES, deserializeState } = require( 'scryptlib' )
const {
  string2Hex, loadTokenContractDesc, compileContract,
  CONTRACT_BRFC_ID,
  BATON_BRFC_ID,
  TOKEN_BRFC_ID,
  SWAP_BRFC_ID,
  changTxForMSB,

  genesisSchema,
  batonSchema,
  tokenSchema,
  TokenValueLen

} = require( '../helper' )

const Signature = bsv.crypto.Signature
const BN = bsv.crypto.BN
const Interpreter = bsv.Script.Interpreter

const inputIndex = 0
const inputSatoshis = 546
const minFee = 546
const dummyTxId1 = '1477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458'
const dummyTxId2 = '2477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458'

const dummyTxId = 'a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458'
const reversedDummyTxId = '5884e5db9de218238671572340b207ee85b628074e7e467096c267266baf77a4'

const utxo = {
  txId: dummyTxId,
  outputIndex: inputIndex,
  script: '', // placeholder
  satoshis: inputSatoshis
}
const tx = new bsv.Transaction().from( utxo )

const outputAmount = 222222

import { witness0, witness1, witness2, getWitnessByPubKey } from './auth.mock'

describe( 'SWAP UTXO Token', () => {
  let Token, TokenSwap, privateKey1, publicKey1, privateKey2, publicKey2

  before( () => {
    Token = buildContractClass( loadTokenContractDesc( 'Token_desc.json' ) )
    TokenSwap = buildContractClass( loadTokenContractDesc( 'TokenSwap_desc.json' ) )

    privateKey1 = bsv.PrivateKey.fromRandom( 'testnet' )
    publicKey1 = bsv.PublicKey.fromPrivateKey( privateKey1 )
    privateKey2 = bsv.PrivateKey.fromRandom( 'testnet' )
    publicKey2 = bsv.PublicKey.fromPrivateKey( privateKey2 )
  } )

  it( 'swap', () => {
    const sighashType = Signature.SIGHASH_ANYONECANPAY | Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID

    const issuerPrivKey = privateKey1
    const issuerAddress = privateKey1.toAddress()
    const issuerPubKey = publicKey1
    const issuerPKH = bsv.crypto.Hash.sha256ripemd160( issuerPubKey.toBuffer() )

    const maxSupply = new BN( 0 )
    const witnessAddress = publicKey1.toAddress()
    const contractIdA = dummyTxId1
    const contractIdB = dummyTxId2
    const prevOutpoint = reversedDummyTxId + '00000000'
    const holderSatoshi = 546
    const NOTIFY_SATOSHI = 546
    const toAddress = privateKey2.toAddress()
    const changeAddress = privateKey1.toAddress()

    const tokenA = new Token(
      new Bytes(contractIdA),
      [
        BigInt(0),
        witness0.pubKey,
        witness1.pubKey,
        witness2.pubKey
      ],
      25 )
    console.log(tokenA.asmVars)
    // const asmVars = token.asmVars
    // const witnessList = [
    //   bin2num(asmVars['witness[0]']),
    //   bin2num(asmVars['witness[1]']),
    //   bin2num(asmVars['witness[2]']),
    //   bin2num(asmVars['witness[3]'])
    // ]

    const tokenB = new Token(
      new Bytes(contractIdB),
      [
        BigInt(0),
        witness0.pubKey,
        witness1.pubKey,
        witness2.pubKey
      ],
      25 )
    console.log(tokenB.asmVars)
    const asmVars = tokenB.asmVars
    const witnessList = [
      bin2num(asmVars['witnesses[0]']),
      bin2num(asmVars['witnesses[1]']),
      bin2num(asmVars['witnesses[2]']),
      bin2num(asmVars['witnesses[3]'])
    ]

    console.log( tokenB.codePart.toASM() )

    const tokenA_CodeScript = tokenA.codePart.toBuffer()
    const tokenA_Hash = bsv.crypto.Hash.sha256ripemd160( tokenA_CodeScript )

    const tokenB_CodeScript = tokenB.codePart.toBuffer()
    const tokenB_Hash = bsv.crypto.Hash.sha256ripemd160( tokenB_CodeScript )

    const swap = new TokenSwap(
      new Ripemd160( toHex( tokenA_Hash ) ),
      new Ripemd160( toHex( tokenB_Hash ) ),
      new Bytes(contractIdA),
      new Bytes(contractIdB),
      new Ripemd160( toHex( issuerAddress.hashBuffer) ),
      witness0.pubKey
    )

    // make a copy since it will be mutated
    const tx0 = bsv.Transaction.shallowCopy( tx )

    const swapLockingScript = new bsv.Script(swap.lockingScript)

    tx0.addOutput( new bsv.Transaction.Output( {
      script: swapLockingScript,
      satoshis: holderSatoshi
    } ) )

    // code part

    const tokenAuthCount = 0
    const tokenSupply = 1000

    //
    const witness = getWitnessByPubKey(witness0.pubKey)
    const { signature: rabinSigs, paddingBytes, order } = witness.swap({
      contractIdA: contractIdA,
      buyerPKH: toHex( toAddress.hashBuffer ),
      tokenA_Amount: tokenSupply,
      contractIdB: contractIdB,
      sellerPKH: toHex( issuerAddress.hashBuffer ), // Mock
      tokenB_Amount: tokenSupply - 300, // Mock
      changeTokenB_Amount: 300, // Mock
      outpoint: reversedDummyTxId + num2bin(inputIndex, 4) // Mock
    })

    console.log(order)

    const tokenA_Data = serializeState({
      amount: num2bin(order.tokenA_Amount, TokenValueLen),
      authCount: 0,
      holderPKH: toHex(toAddress.hashBuffer),
      brfc: TOKEN_BRFC_ID
    }, STATE_LEN_2BYTES, tokenSchema)

    const tokenA_LockingScript = tokenA.codePart.toASM() + ' ' + tokenA_Data
    // console.log(tokenLockingScript)
    const tokenA_Script = bsv.Script.fromASM( tokenA_LockingScript )

    //
    tx0.addOutput( new bsv.Transaction.Output( {
      script: tokenA_Script,
      satoshis: holderSatoshi
    } ) )

    const tokenB_Data = serializeState({
      amount: num2bin(order.tokenB_Amount, TokenValueLen),
      authCount: 0,
      holderPKH: toHex(issuerAddress.hashBuffer),
      brfc: TOKEN_BRFC_ID
    }, STATE_LEN_2BYTES, tokenSchema)

    const tokenB_LockingScript = tokenB.codePart.toASM() + ' ' + tokenB_Data
    // console.log(tokenLockingScript)
    const tokenB_Script = bsv.Script.fromASM( tokenB_LockingScript )

    //
    tx0.addOutput( new bsv.Transaction.Output( {
      script: tokenB_Script,
      satoshis: holderSatoshi
    } ) )

    const changeToken_Data = serializeState({
      amount: num2bin(order.changeTokenB_Amount, TokenValueLen),
      authCount: 0,
      holderPKH: toHex(changeAddress.hashBuffer),
      brfc: TOKEN_BRFC_ID
    }, STATE_LEN_2BYTES, tokenSchema)

    const changeToken_LockingScript = tokenB.codePart.toASM() + ' ' + changeToken_Data
    // console.log(tokenLockingScript)
    const changeToken_Script = bsv.Script.fromASM( changeToken_LockingScript )

    //
    tx0.addOutput( new bsv.Transaction.Output( {
      script: changeToken_Script,
      satoshis: holderSatoshi
    } ) )

    // Notify owner
    tx0.addOutput( new bsv.Transaction.Output( {
      script: bsv.Script.buildPublicKeyHashOut( toAddress ),
      satoshis: NOTIFY_SATOSHI
    } ) )

    const prevLockingScript = swap.lockingScript.toASM()
    const preimage = getPreimage( tx0, prevLockingScript, inputSatoshis, 0, sighashType )
    console.log( preimage.outpoint )

    expect(toHex( swap.lockingScript.toBuffer())).is.eql(preimage.scriptCode)

    const prevOutput = ''

    // console.log( new Ripemd160( toHex( toAddress.hashBuffer ) ), new Int( order.tokenAmount ), new Ripemd160( toHex( issuerAddress.hashBuffer ) ), new Int( order.satoshiAmount ), new Ripemd160( toHex( changeAddress.hashBuffer ) ), NOTIFY_SATOSHI, holderSatoshi, new Bytes(prevOutput), new Bytes(toHex( tokenCodeScript)), preimage, rabinSigs, new Bytes(paddingBytes) )

    const swapFn = swap.swap( new Ripemd160( toHex( toAddress.hashBuffer ) ), new Int( order.tokenA_Amount ), new Ripemd160( toHex( issuerAddress.hashBuffer ) ), new Int( order.tokenB_Amount ), new Ripemd160( toHex( changeAddress.hashBuffer ) ), new Int( order.changeTokenB_Amount ), NOTIFY_SATOSHI, holderSatoshi, new Bytes(prevOutput), new Bytes(toHex( tokenA_CodeScript)), new Bytes(toHex( tokenB_CodeScript)), preimage, rabinSigs, new Bytes(paddingBytes) )

    const unlockingScript = swapFn.toScript()

    console.log( `TransferUnlockingScriptSize=${unlockingScript.toBuffer().length}` )

    tx0.inputs[ 0 ].output = new bsv.Transaction.Output( {
      script: bsv.Script.fromASM( prevLockingScript ),
      satoshis: inputSatoshis
    } )
    tx0.inputs[ 0 ].setScript( unlockingScript )

    console.log( tx0 )


    console.log( 'Pre-Transaction Size', tx0._estimateFee() )

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
    // console.log( `"hex": "${tx0.serialize()}"`, inputIndex, inputSatoshis )
    const result = swapFn.verify( context )

    console.log( `SaleUnlockingScriptSize=${unlockingScript.toBuffer().length}` )
    console.log( 'Swap Size', swap.lockingScript.toHex().length / 2 )
    console.log( 'Token Size', tokenA.lockingScript.toHex().length / 2 )

    // console.log( result )
    expect( result.success, result.error ).to.be.true
  } )
} )
