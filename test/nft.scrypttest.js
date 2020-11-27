/* eslint-disable no-unused-expressions */
const console = require( 'tracer' ).colorConsole()
const { expect } = require( 'chai' )
const { bsv, buildContractClass, signTx, toHex, getPreimage, Sig, Int, PubKey, Ripemd160, SigHashPreimage, sighashType2Hex, Bytes, serializeState, STATE_LEN_2BYTES, STATE_LEN_4BYTES, deserializeState } = require( 'scryptlib' )
const {
  string2Hex, loadTokenContractDesc, compileContract,
  CONTRACT_BRFC_ID,
  BATON_BRFC_ID,
  TOKEN_BRFC_ID,
  NFT_CONTRACT_BRFC_ID,
  NFT_BATON_BRFC_ID,
  NFT_TOKEN_BRFC_ID,
  NFT_SALE_BRFC_ID,
  NFT_SWAP_BRFC_ID,
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

describe( 'Controlled NFT-UTXO Token', () => {
  let NFT, privateKey1, publicKey1, privateKey2, publicKey2

  before( () => {
    NFT = buildContractClass( loadTokenContractDesc( 'NFT_desc.json' ) )
    // Token = buildContractClass( compileContract( 'FungibleTokenUtxo.scrypt' ) )
    // console.log( Token )

    privateKey1 = bsv.PrivateKey.fromRandom( 'testnet' )
    publicKey1 = bsv.PublicKey.fromPrivateKey( privateKey1 )
    privateKey2 = bsv.PrivateKey.fromRandom( 'testnet' )
    publicKey2 = bsv.PublicKey.fromPrivateKey( privateKey2 )
  } )

  it( 'Transfer 1-1', () => {
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

    // data + dataLen(4bytes) + NFT_TOKEN_BRFC_ID(6bytes) + contractId(32bytes) + expire(4bytes) + authCount(1byte) + ownerPkh(20bytes) =
    const token = new NFT( new Ripemd160( toHex( witnessAddress.hashBuffer ) ), [
      BigInt(0),
      witness0.pubKey,
      witness1.pubKey,
      witness2.pubKey
    ], 25 )
    console.log( token.asmVars )
    const asmVars = token.asmVars
    const witnessList = [
      bin2num(asmVars['witness[0]']),
      bin2num(asmVars['witness[1]']),
      bin2num(asmVars['witness[2]']),
      bin2num(asmVars['witness[3]'])
    ]

    const data = Buffer.from( 'Hello NFT World'.repeat(2560), 'utf8' )
    // 
    const expire = parseInt(Date.now() / 1000 + 365 * 24 * 60 * 60 )
    const tokenData = toHex( data ) + num2bin( data.length, 4 ) + NFT_TOKEN_BRFC_ID + contractId + num2bin( expire, 4 ) + num2bin( 0, 1 ) + toHex( ownerAddress.hashBuffer )

    token.setDataPart( tokenData )
    console.log( token )

    console.log( token.lockingScript.toASM() )
    console.log( token.lockingScript.toHex() )

    console.log( token.codePart.toASM() )
    console.log( token.dataPart.toASM() )

    // make a copy since it will be mutated
    const tx0 = bsv.Transaction.shallowCopy( tx )

    // code part
    const lockingBodyScript = token.codePart.toASM()

    // 
    //  UTXO Token LockingScript

    const newTokenData = toHex( data ) + num2bin( data.length, 4 ) + NFT_TOKEN_BRFC_ID + contractId + num2bin( expire, 4 ) + num2bin( 0, 1 ) + toHex( toAddress.hashBuffer )

    const newTokenLockingScript = lockingBodyScript + ' ' + newTokenData
    const newTokenScript = bsv.Script.fromASM( newTokenLockingScript )

    tx0.addOutput( new bsv.Transaction.Output( {
      script: newTokenScript,
      satoshis: holderSatoshi
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

    // 
    const sig = signTx( tx0, ownerPrivKey, prevLockingScript, inputSatoshis, 0, sighashType )

    const prevOutput = ''

    const transferFn = token.transfer( new Sig( toHex( sig ) ), new PubKey( toHex( ownerPubKey ) ), new Ripemd160( toHex( toAddress.hashBuffer ) ), new Ripemd160( toHex( changeAddress.hashBuffer ) ), changeSatoshi, holderSatoshi, new Bytes( prevOutput ), preimage, rabinSigs, paddingBytes )

    const unlockingScript = transferFn.toScript()

    console.log( `TransferUnlockingScriptSize=${unlockingScript.toBuffer().length}` )

    tx0.inputs[ 0 ].output = new bsv.Transaction.Output( {
      script: bsv.Script.fromASM( prevLockingScript ),
      satoshis: inputSatoshis
    } )
    tx0.inputs[ 0 ].setScript( unlockingScript )

    console.log( tx0 )

    const context = { tx: tx0, inputIndex, inputSatoshis }
    // console.log( `"hex": "${tx0.serialize()}"`, inputIndex, inputSatoshis )
    const result = transferFn.verify( context )

    console.log( `TransferUnlockingScriptSize=${unlockingScript.toBuffer().length}` )
    console.log( 'Token Size', token.lockingScript.toHex().length / 2 )
    console.log( 'Transaction Size', tx0.serialize().length / 2 )

    // console.log( result )
    expect( result.success, result.error ).to.be.true
  } )

  it( 'Transfer 1-1 with preOutput', () => {
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

    // data + dataLen(4bytes) + NFT_TOKEN_BRFC_ID(6bytes) + contractId(32bytes) + authCount(1byte) + ownerPkh(20bytes) =
    const token = new NFT( new Ripemd160( toHex( witnessAddress.hashBuffer ) ), [
      BigInt(0),
      witness0.pubKey,
      witness1.pubKey,
      witness2.pubKey
    ], 25 )
    console.log( token.asmVars )
    const asmVars = token.asmVars
    const witnessList = [
      bin2num(asmVars['witness[0]']),
      bin2num(asmVars['witness[1]']),
      bin2num(asmVars['witness[2]']),
      bin2num(asmVars['witness[3]'])
    ]

    const data = Buffer.from( 'Hello NFT World'.repeat(2560), 'utf8' )
    // 
    const expire = parseInt(Date.now() / 1000 + 365 * 24 * 60 * 60 )
    const tokenData = toHex( data ) + num2bin( data.length, 4 ) + NFT_TOKEN_BRFC_ID + contractId + num2bin( expire, 4 ) + num2bin( 0, 1 ) + toHex( ownerAddress.hashBuffer )

    token.setDataPart( tokenData )
    console.log( token )

    console.log( token.lockingScript.toASM() )
    console.log( token.lockingScript.toHex() )

    console.log( token.codePart.toASM() )
    console.log( token.dataPart.toASM() )

    // make a copy since it will be mutated
    const tx0 = bsv.Transaction.shallowCopy( tx )

    // code part
    const lockingBodyScript = token.codePart.toASM()

    // 
    const prevScript = bsv.Script.buildPublicKeyHashOut( ownerAddress )
    const prevSatoshi = 5000
    tx0.addOutput( new bsv.Transaction.Output( {
      script: prevScript,
      satoshis: prevSatoshi
    } ) )

    // 
    const prevOutput = tx0.outputs[ 0 ].toBufferWriter().toBuffer().toString( 'hex' )
    console.log( prevOutput )

    // 
    //  UTXO Token LockingScript

    const newTokenData = toHex( data ) + num2bin( data.length, 4 ) + NFT_TOKEN_BRFC_ID + contractId + num2bin( expire, 4 ) + num2bin( 0, 1 ) + toHex( toAddress.hashBuffer )

    const newTokenLockingScript = lockingBodyScript + ' ' + newTokenData
    const newTokenScript = bsv.Script.fromASM( newTokenLockingScript )

    tx0.addOutput( new bsv.Transaction.Output( {
      script: newTokenScript,
      satoshis: holderSatoshi
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

    // 
    const sig = signTx( tx0, ownerPrivKey, prevLockingScript, inputSatoshis, 0, sighashType )

    const transferFn = token.transfer( new Sig( toHex( sig ) ), new PubKey( toHex( ownerPubKey ) ), new Ripemd160( toHex( toAddress.hashBuffer ) ), new Ripemd160( toHex( changeAddress.hashBuffer ) ), changeSatoshi, holderSatoshi, new Bytes( prevOutput ), preimage, rabinSigs, paddingBytes )

    const unlockingScript = transferFn.toScript()

    console.log( `TransferUnlockingScriptSize=${unlockingScript.toBuffer().length}` )

    tx0.inputs[ 0 ].output = new bsv.Transaction.Output( {
      script: bsv.Script.fromASM( prevLockingScript ),
      satoshis: inputSatoshis
    } )
    tx0.inputs[ 0 ].setScript( unlockingScript )

    console.log( tx0 )

    const context = { tx: tx0, inputIndex, inputSatoshis }
    // console.log( `"hex": "${tx0.serialize()}"`, inputIndex, inputSatoshis )
    const result = transferFn.verify( context )

    console.log( `TransferUnlockingScriptSize=${unlockingScript.toBuffer().length}` )
    console.log( 'Token Size', token.lockingScript.toHex().length / 2 )
    console.log( 'Transaction Size', tx0.serialize().length / 2 )

    // console.log( result )
    expect( result.success, result.error ).to.be.true
  } )

  it( 'Transfer 1-1 with preOutput and change == zero', () => {
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

    // data + dataLen(4bytes) + NFT_TOKEN_BRFC_ID(6bytes) + contractId(32bytes) + authCount(1byte) + ownerPkh(20bytes) =
    const token = new NFT( new Ripemd160( toHex( witnessAddress.hashBuffer ) ), [
      BigInt(0),
      witness0.pubKey,
      witness1.pubKey,
      witness2.pubKey
    ], 25 )
    console.log( token.asmVars )
    const asmVars = token.asmVars
    const witnessList = [
      bin2num(asmVars['witness[0]']),
      bin2num(asmVars['witness[1]']),
      bin2num(asmVars['witness[2]']),
      bin2num(asmVars['witness[3]'])
    ]

    const data = Buffer.from( 'Hello NFT World'.repeat(2560), 'utf8' )
    // 
    const expire = parseInt(Date.now() / 1000 + 365 * 24 * 60 * 60 )
    const tokenData = toHex( data ) + num2bin( data.length, 4 ) + NFT_TOKEN_BRFC_ID + contractId + num2bin( expire, 4 ) + num2bin( 0, 1 ) + toHex( ownerAddress.hashBuffer )

    token.setDataPart( tokenData )
    console.log( token )

    console.log( token.lockingScript.toASM() )
    console.log( token.lockingScript.toHex() )

    console.log( token.codePart.toASM() )
    console.log( token.dataPart.toASM() )

    // make a copy since it will be mutated
    const tx0 = bsv.Transaction.shallowCopy( tx )

    // code part
    const lockingBodyScript = token.codePart.toASM()

    // 
    const prevScript = bsv.Script.buildPublicKeyHashOut( ownerAddress )
    const prevSatoshi = 5000
    tx0.addOutput( new bsv.Transaction.Output( {
      script: prevScript,
      satoshis: prevSatoshi
    } ) )

    // 
    const prevOutput = tx0.outputs[ 0 ].toBufferWriter().toBuffer().toString( 'hex' )
    console.log( prevOutput )

    // 
    //  UTXO Token LockingScript

    const newTokenData = toHex( data ) + num2bin( data.length, 4 ) + NFT_TOKEN_BRFC_ID + contractId + num2bin( expire, 4 ) + num2bin( 0, 1 ) + toHex( toAddress.hashBuffer )

    const newTokenLockingScript = lockingBodyScript + ' ' + newTokenData
    const newTokenScript = bsv.Script.fromASM( newTokenLockingScript )

    tx0.addOutput( new bsv.Transaction.Output( {
      script: newTokenScript,
      satoshis: holderSatoshi
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

    const changeSatoshi = 0
    // tx0.addOutput( new bsv.Transaction.Output( {
    //   script: bsv.Script.buildPublicKeyHashOut( changeAddress ),
    //   satoshis: changeSatoshi
    // } ) )

    // console.log(tx1.toObject())

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

    // 
    const sig = signTx( tx0, ownerPrivKey, prevLockingScript, inputSatoshis, 0, sighashType )

    const transferFn = token.transfer( new Sig( toHex( sig ) ), new PubKey( toHex( ownerPubKey ) ), new Ripemd160( toHex( toAddress.hashBuffer ) ), new Ripemd160( toHex( changeAddress.hashBuffer ) ), changeSatoshi, holderSatoshi, new Bytes( prevOutput ), preimage, rabinSigs, paddingBytes )

    const unlockingScript = transferFn.toScript()

    console.log( `TransferUnlockingScriptSize=${unlockingScript.toBuffer().length}` )

    tx0.inputs[ 0 ].output = new bsv.Transaction.Output( {
      script: bsv.Script.fromASM( prevLockingScript ),
      satoshis: inputSatoshis
    } )
    tx0.inputs[ 0 ].setScript( unlockingScript )

    console.log( tx0 )

    const context = { tx: tx0, inputIndex, inputSatoshis }
    // console.log( `"hex": "${tx0.serialize()}"`, inputIndex, inputSatoshis )
    const result = transferFn.verify( context )

    console.log( `TransferUnlockingScriptSize=${unlockingScript.toBuffer().length}` )
    console.log( 'Token Size', token.lockingScript.toHex().length / 2 )
    console.log( 'Transaction Size', tx0.serialize().length / 2 )

    // console.log( result )
    expect( result.success, result.error ).to.be.true
  } )
} )
