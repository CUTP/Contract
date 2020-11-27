/* eslint-disable no-unused-expressions */
const console = require( 'tracer' ).colorConsole()
const { expect } = require( 'chai' )
const { bsv, buildContractClass, signTx, toHex, getPreimage, Sig, Int, PubKey, Ripemd160, SigHashPreimage, sighashType2Hex, Bytes, serializeState, STATE_LEN_2BYTES, deserializeState } = require( 'scryptlib' )
const {
  string2Hex, loadTokenContractDesc, compileContract,
  CONTRACT_BRFC_ID,
  BATON_BRFC_ID,
  TOKEN_BRFC_ID,
  SALE_BRFC_ID,
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

import { witness0, witness1, witness2, getWitnessByPubKey } from './auth.mock'

describe( 'Sale UTXO Token', () => {
  let Genesis, Baton, Token, TokenSale, privateKey1, publicKey1, privateKey2, publicKey2

  before( () => {
    Genesis = buildContractClass( loadTokenContractDesc( 'Genesis_desc.json' ) )
    Baton = buildContractClass( loadTokenContractDesc( 'Baton_desc.json' ) )
    Token = buildContractClass( loadTokenContractDesc( 'Token_desc.json' ) )
    TokenSale = buildContractClass( loadTokenContractDesc( 'TokenSale_desc.json' ) )
    // Token = buildContractClass( compileContract( 'FungibleTokenUtxo.scrypt' ) )
    // console.log( Token )

    privateKey1 = bsv.PrivateKey.fromRandom( 'testnet' )
    publicKey1 = bsv.PublicKey.fromPrivateKey( privateKey1 )
    privateKey2 = bsv.PrivateKey.fromRandom( 'testnet' )
    publicKey2 = bsv.PublicKey.fromPrivateKey( privateKey2 )
  } )

  it( 'sale', () => {
    const sighashType = Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID

    const issuerPrivKey = privateKey1
    const issuerAddress = privateKey1.toAddress()
    const issuerPubKey = publicKey1
    const issuerPKH = bsv.crypto.Hash.sha256ripemd160( issuerPubKey.toBuffer() )

    const maxSupply = new BN( 0 )
    const witnessAddress = publicKey1.toAddress()
    const contractId = dummyTxId
    const prevOutpoint = reversedDummyTxId + '00000000'
    const holderSatoshi = 546
    const NOTIFY_SATOSHI = 546
    const toAddress = privateKey2.toAddress()
    const changeAddress = privateKey1.toAddress()

    const token = new Token(
      new Bytes(TOKEN_BRFC_ID),
      new Bytes(contractId),
      new Ripemd160( toHex( witnessAddress.hashBuffer ) ),
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
      bin2num(asmVars['witness[0]']),
      bin2num(asmVars['witness[1]']),
      bin2num(asmVars['witness[2]']),
      bin2num(asmVars['witness[3]'])
    ]

    // code part
    console.log( token.codePart.toASM() )

    const tokenCodeScriptASM = token.codePart.toASM()
    const tokenCodeScript = token.codePart.toBuffer()
    const tokenHash = bsv.crypto.Hash.sha256ripemd160( tokenCodeScript )

    const sale = new TokenSale(
      new Bytes(SALE_BRFC_ID),
      new Bytes(contractId),
      new Ripemd160( toHex( witnessAddress.hashBuffer ) ),
      new Ripemd160( toHex( tokenHash ) ),
      new Ripemd160( toHex( issuerAddress.hashBuffer) ),
      witness0.pubKey
    )
    console.log(sale.asmVars)

    // make a copy since it will be mutated
    const tx0 = bsv.Transaction.shallowCopy( tx )

    const saleLockingScript = new bsv.Script(sale.lockingScript)

    tx0.addOutput( new bsv.Transaction.Output( {
      script: saleLockingScript,
      satoshis: holderSatoshi
    } ) )

    const tokenAuthCount = 0
    const tokenSupply = 300

    // 
    const witness = getWitnessByPubKey(witness0.pubKey)
    const { signature: rabinSigs, paddingBytes, order } = witness.sale({
      contractId: contractId,
      buyerPKH: toHex( toAddress.hashBuffer ),
      tokenAmount: tokenSupply,
      sellerPKH: toHex( issuerAddress.hashBuffer ) // Mock
    })

    console.log(order)

    // count(1byte) + ownerPkh(20bytes) + tokenAmount(32bytes) = 91bytes(5b)
    const tokenData = num2bin( tokenAuthCount, 1 ) + toHex( toAddress.hashBuffer ) + num2bin( order.tokenAmount, 32 )
    const tokenLockingScript = tokenCodeScriptASM + ' ' + tokenData
    console.log(tokenLockingScript)
    const tokenScript = bsv.Script.fromASM( tokenLockingScript )
    console.log(tokenScript.toBuffer().toString('hex'))

    // 
    tx0.addOutput( new bsv.Transaction.Output( {
      script: tokenScript,
      satoshis: holderSatoshi
    } ) )

    // 给发行者币
    tx0.addOutput( new bsv.Transaction.Output( {
      script: bsv.Script.buildPublicKeyHashOut( issuerAddress ),
      satoshis: order.satoshiAmount
    } ) )

    // Notify owner
    tx0.addOutput( new bsv.Transaction.Output( {
      script: bsv.Script.buildPublicKeyHashOut( toAddress ),
      satoshis: NOTIFY_SATOSHI
    } ) )

    // Notify witness
    tx0.addOutput( new bsv.Transaction.Output( {
      script: bsv.Script.buildPublicKeyHashOut( witnessAddress ),
      satoshis: NOTIFY_SATOSHI
    } ) )

    // change
    // tx1.change( changeAddress )
    // const changeSatoshi = tx1.outputs[ tx1.outputs.length - 1 ].satoshis

    const changeSatoshi = 1000
    tx0.addOutput( new bsv.Transaction.Output( {
      script: bsv.Script.buildPublicKeyHashOut( changeAddress ),
      satoshis: changeSatoshi
    } ) )

    // console.log(tx1.toObject())

    const prevLockingScript = sale.lockingScript.toASM()
    const preimage = getPreimage( tx0, prevLockingScript, inputSatoshis, 0, sighashType )
    console.log( preimage.outpoint )

    expect(toHex( saleLockingScript.toBuffer())).is.eql(preimage.scriptCode)

    const prevOutput = ''

    console.log( new Ripemd160( toHex( toAddress.hashBuffer ) ), new Int( order.tokenAmount ), new Ripemd160( toHex( issuerAddress.hashBuffer ) ), new Int( order.satoshiAmount ), new Ripemd160( toHex( changeAddress.hashBuffer ) ), changeSatoshi, holderSatoshi, new Bytes(prevOutput), new Bytes(toHex( tokenCodeScript)), preimage, rabinSigs, new Bytes(paddingBytes) )

    const buyFn = sale.buy( new Ripemd160( toHex( toAddress.hashBuffer ) ), new Int( order.tokenAmount ), new Ripemd160( toHex( issuerAddress.hashBuffer ) ), new Int( order.satoshiAmount ), new Ripemd160( toHex( changeAddress.hashBuffer ) ), changeSatoshi, holderSatoshi, new Bytes(prevOutput), new Bytes(toHex( tokenCodeScript)), preimage, rabinSigs, new Bytes(paddingBytes) )

    const unlockingScript = buyFn.toScript()

    console.log( `TransferUnlockingScriptSize=${unlockingScript.toBuffer().length}` )

    tx0.inputs[ 0 ].output = new bsv.Transaction.Output( {
      script: bsv.Script.fromASM( prevLockingScript ),
      satoshis: inputSatoshis
    } )
    tx0.inputs[ 0 ].setScript( unlockingScript )

    console.log( tx0 )

    const context = { tx: tx0, inputIndex, inputSatoshis }
    // console.log( `"hex": "${tx0.serialize()}"`, inputIndex, inputSatoshis )
    const result = buyFn.verify( context )

    console.log( `SaleUnlockingScriptSize=${unlockingScript.toBuffer().length}` )
    console.log( 'Sale Size', sale.lockingScript.toHex().length / 2 )
    console.log( 'Token Size', token.lockingScript.toHex().length / 2 )

    // console.log( result )
    expect( result.success, result.error ).to.be.true
  } )
} )
