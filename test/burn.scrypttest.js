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
const inputSatoshis = 100000
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

import { witness0, witness1, witness2 } from './auth.mock'

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

  it( 'Burn', () => {
    const sighashType = Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID

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
    const tx1 = bsv.Transaction.shallowCopy( tx )

    const changeSatoshi = 1000
    tx1.addOutput( new bsv.Transaction.Output( {
      script: bsv.Script.buildPublicKeyHashOut( changeAddress ),
      satoshis: changeSatoshi
    } ) )

    // console.log(tx1.toObject())

    const prevLockingScript = token.lockingScript.toASM()

    const preimage = getPreimage( tx1, prevLockingScript, inputSatoshis, 0, sighashType )
    console.log( preimage.outpoint )

    const sig = signTx( tx1, ownerPrivKey, prevLockingScript, inputSatoshis, 0, sighashType )

    const burnFn = token.burn( new Sig( toHex( sig ) ), new PubKey( toHex( ownerPubKey ) ), new SigHashPreimage( toHex( preimage ) ) )

    const unlockingScript = burnFn.toScript()

    tx1.inputs[ 0 ].output = new bsv.Transaction.Output( {
      script: bsv.Script.fromASM( prevLockingScript ),
      satoshis: inputSatoshis
    } )
    tx1.inputs[ 0 ].setScript( unlockingScript )

    console.log( tx1 )

    const context = { tx: tx1, inputIndex, inputSatoshis }
    console.log( `"hex": "${tx1.serialize()}"`, inputIndex, inputSatoshis )
    const result = burnFn.verify( context )

    console.log( `BurnUnlockingScriptSize=${unlockingScript.toBuffer().length}` )

    console.log( result )
    expect( result.success, result.error ).to.be.true
  } )
} )
