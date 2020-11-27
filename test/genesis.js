/* eslint-disable no-unused-expressions */
const console = require( 'tracer' ).colorConsole()
const { expect } = require( 'chai' )
const { bsv, buildContractClass, signTx, toHex, getPreimage, Sig, Int, PubKey, Ripemd160, SigHashPreimage, sighashType2Hex, Bytes, serializeState, STATE_LEN_2BYTES, deserializeState } = require( 'scryptlib' )
const {
  string2Hex, loadTokenContractDesc, compileContract,
  CONTRACT_BRFC_ID,
  BATON_BRFC_ID,
  TOKEN_BRFC_ID,
  num2bin, bin2num,
  changTxForMSB

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

import { RabinAuth } from './auth.mock'
console.log(RabinAuth)

describe( 'Controlled UTXO Token', () => {
  let Genesis, Baton, Token, privateKey1, publicKey1, privateKey2, publicKey2
  const rabinAuth = new RabinAuth()

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

  it( '首次发行', () => {
    const issuerPrivKey = privateKey1
    const issuerAddress = privateKey1.toAddress()
    const issuerPubKey = publicKey1

    const witnessAddress = publicKey1.toAddress()

    const genesisSchema = {
      brfc: 'bytes',
      name: 'string',
      symbol: 'string',
      issuer: 'string',
      domain: 'string',
      rule: 'number',
      decimals: 'number'
    }

    const data = {
      brfc: CONTRACT_BRFC_ID,
      name: 'Test CUTP Token',
      symbol: 'TFT',
      issuer: 'ChainBow Co. Ltd.',
      domain: 'chainbow.io',
      rule: 0,
      decimals: 0
    }

    const genesis = new Genesis()
    const asmVarsGenesis = {
      'Genesis.initiate.pkh': toHex(issuerAddress.hashBuffer)
    }
    genesis.replaceAsmVars(asmVarsGenesis)
    console.log(genesis.asmVars)
    const contractData = serializeState(data, STATE_LEN_2BYTES, genesisSchema )
    console.log( genesis )

    genesis.setDataPart( contractData )
    console.log( genesis )

    console.log( genesis.lockingScript.toASM() )
    console.log( genesis.lockingScript.toHex() )

    console.log( genesis.codePart.toASM() )
    console.log( genesis.dataPart.toASM() )

    const deStates = deserializeState(genesis.dataPart.toHex(), genesisSchema)
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

    // 
    // Baton Token LockingScript
    const batonSchema = {
      brfc: 'bytes',
      contractId: 'bytes'
    }

    // 
    const baton = new Baton(new Ripemd160(toHex(issuerAddress.hashBuffer)), rabinAuth.pubKey)

    console.log(baton.asmVars)

    const batonData = serializeState({
      brfc: BATON_BRFC_ID,
      contractId: contractId
    }, STATE_LEN_2BYTES, batonSchema )
    console.log( baton )

    baton.setDataPart( batonData )
    console.log( baton )

    console.log( baton.lockingScript.toASM() )
    console.log( baton.lockingScript.toHex() )

    console.log( baton.codePart.toASM() )
    console.log( baton.dataPart.toASM() )

    console.log(deserializeState(baton.dataPart.toHex(), batonSchema))

    const batonScript = baton.lockingScript

    tx0.addOutput( new bsv.Transaction.Output( {
      script: batonScript,
      satoshis: holderSatoshi
    } ) )

    const changeSatoshi = 1000
    tx0.addOutput( new bsv.Transaction.Output( {
      script: bsv.Script.buildPublicKeyHashOut( changeAddress ),
      satoshis: changeSatoshi
    } ) )

    // console.log(tx1.toObject())
    const prevLockingScript = genesis.lockingScript.toASM()

    // 
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
    console.log( 'Transaction Size', tx0.serialize().length / 2 )

    console.log( result )
    expect( result.success, result.error ).to.be.true
  } )
} )
