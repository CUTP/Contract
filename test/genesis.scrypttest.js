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

  GenesisSchema,
  BatonSchema,
  TokenSchema

} = require( '../helper' )

import { witness0, witness1, witness2, getWitnessByPubKey } from './auth.mock'

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

  it( 'Genesis & Issue', () => {
    const issuerPrivKey = privateKey1
    const issuerAddress = privateKey1.toAddress()
    const issuerPubKey = publicKey1

    const witnessAddress = publicKey1.toAddress()

    const genesis = new Genesis()
    const asmVarsGenesis = {
      'Genesis.initiate.pkh': toHex(issuerAddress.hashBuffer)
    }
    genesis.replaceAsmVars(asmVarsGenesis)
    console.log(genesis.asmVars)
    // OPRETURN STATE CONTRACT_BRFC_ID
    const contractData = serializeState({
      name: 'Test CUTP Token',
      symbol: 'TFT',
      issuer: 'ChainBow Co. Ltd.',
      domain: 'chainbow.io',
      rule: 0,
      decimals: 0,
      brfc: CONTRACT_BRFC_ID
    }, STATE_LEN_2BYTES, GenesisSchema)
    genesis.setDataPart( contractData )
    console.log( genesis )

    console.log( genesis.lockingScript.toASM() )
    console.log( genesis.lockingScript.toHex() )

    console.log( genesis.codePart.toASM() )
    console.log( genesis.dataPart.toASM() )

    const deStates = deserializeState(genesis.dataPart.toHex(), GenesisSchema)
    console.log(deStates)

    const sighashType = Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID
    // make a copy since it will be mutated
    const tx0 = bsv.Transaction.shallowCopy( tx )

    const contractId = dummyTxId
    const prevOutpoint = reversedDummyTxId + '00000000'
    const ownerAddress = privateKey2.toAddress()
    const initialSupply = 1024
    const holderSatoshi = 546
    const NOTIFY_SATOSHI = 546
    const changeAddress = privateKey2.toAddress()

    // 非标输出，0
    // 创建 Baton Token LockingScript

    // 认证用公钥
    const baton = new Baton(
      new Bytes(contractId),
      [
        BigInt(0),
        witness0.pubKey,
        witness1.pubKey,
        witness2.pubKey
      ])
    console.log(baton.asmVars)

    // OP_RETURN supply issuerPKH BATON_BRFC_ID
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

    const batonScript = baton.lockingScript

    tx0.addOutput( new bsv.Transaction.Output( {
      script: batonScript,
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
      holderPKH: toHex(issuerAddress.hashBuffer),
      brfc: TOKEN_BRFC_ID
    }, STATE_LEN_2BYTES, TokenSchema)

    token.setDataPart(tokenData)

    const tokenScript = token.lockingScript

    tx0.addOutput( new bsv.Transaction.Output( {
      script: tokenScript,
      satoshis: holderSatoshi
    } ) )

    const changeSatoshi = 1000
    tx0.addOutput( new bsv.Transaction.Output( {
      script: bsv.Script.buildPublicKeyHashOut( changeAddress ),
      satoshis: changeSatoshi
    } ) )

    // console.log(tx1.toObject())
    const prevLockingScript = genesis.lockingScript.toASM()

    const sig = signTx( tx0, issuerPrivKey, prevLockingScript, inputSatoshis, 0, sighashType )

    const initiateFn = genesis.initiate( new Sig( toHex( sig ) ), new PubKey( toHex( issuerPubKey ) ) )

    const unlockingScript = initiateFn.toScript()

    tx0.inputs[ 0 ].output = new bsv.Transaction.Output( {
      script: bsv.Script.fromASM( prevLockingScript ),
      satoshis: inputSatoshis
    } )
    tx0.inputs[ 0 ].setScript( unlockingScript )

    console.log( tx0 )

    const context = { tx: tx0, inputIndex, inputSatoshis }
    console.log( `"hex": "${tx0.serialize()}"`, inputIndex, inputSatoshis )
    const result = initiateFn.verify( context )

    console.log( `InitiateUnlockingScriptSize=${unlockingScript.toBuffer().length}` )

    console.log( 'Genesis Size', genesis.lockingScript.toHex().length / 2 )
    console.log( 'Baton Size', baton.lockingScript.toHex().length / 2 )
    console.log( 'Token Size', token.lockingScript.toHex().length / 2 )
    console.log( 'Transaction Size', tx0.serialize().length / 2 )

    console.log( result )
    expect( result.success, result.error ).to.be.true
  } )
} )
