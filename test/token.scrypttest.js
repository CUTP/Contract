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

    const ownerSupply = 1000
    // authCount(1byte) + ownerPkh(20bytes) + tokenAmount(32bytes) = 91bytes(5b)
    const tokenData = num2bin( 0, 1 ) + toHex( ownerAddress.hashBuffer ) + num2bin( ownerSupply, 32 )
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

    // 
    //  UTXO Token LockingScript
    // prevOutpoint(36bytes) + ownerPkh(20bytes) + tokenAmount(32bytes) = 126bytes(7e)
    const newTokenAuthCount = 0
    const newTokenSupply = 700
    const newTokenData = num2bin( newTokenAuthCount, 1 ) + toHex( toAddress.hashBuffer ) + num2bin( newTokenSupply, 32 )
    const newTokenLockingScript = lockingBodyScript + ' ' + newTokenData
    const newTokenScript = bsv.Script.fromASM( newTokenLockingScript )

    tx0.addOutput( new bsv.Transaction.Output( {
      script: newTokenScript,
      satoshis: holderSatoshi
    } ) )

    const changeTokenAuthCount = 0
    const changeTokenSupply = 300
    const changeTokenData = num2bin( changeTokenAuthCount, 1 ) + toHex( changeAddress.hashBuffer ) + num2bin( changeTokenSupply, 32 )
    const changeTokenLockingScript = lockingBodyScript + ' ' + changeTokenData
    console.log(changeTokenLockingScript)
    const changeTokenScript = bsv.Script.fromASM( changeTokenLockingScript )

    tx0.addOutput( new bsv.Transaction.Output( {
      script: changeTokenScript,
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

    const transferFn = token.transfer( new Sig( toHex( sig ) ), new PubKey( toHex( ownerPubKey ) ), new Ripemd160( toHex( toAddress.hashBuffer ) ), new Int( newTokenSupply ), new Ripemd160( toHex( changeAddress.hashBuffer ) ), new Int( changeTokenSupply ), changeSatoshi, holderSatoshi, new Bytes(''), preimage, rabinSigs, paddingBytes )

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

    const ownerSupply = 1000
    // codePart + OP_RETURN + TOKEN_BRFC_ID(6bytes) + contractId(32bytes) + count(1byte) + ownerPkh(20bytes) + tokenAmount(32bytes) = 91bytes(5b)
    const tokenData = num2bin( 0, 1 ) + toHex( ownerAddress.hashBuffer ) + num2bin( ownerSupply, 32 )
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

    // 
    //  UTXO Token LockingScript
    // codePart + OP_RETURN + TOKEN_BRFC_ID(6bytes) + contractId(32bytes) + prevOutpoint(36bytes) + ownerPkh(20bytes) + tokenAmount(32bytes) = 126bytes(7e)
    const newTokenAuthCount = 0
    const newTokenSupply = 1000
    const newTokenData = num2bin( newTokenAuthCount, 1 ) + toHex( toAddress.hashBuffer ) + num2bin( newTokenSupply, 32 )
    const newTokenLockingScript = lockingBodyScript + ' ' + newTokenData
    const newTokenScript = bsv.Script.fromASM( newTokenLockingScript )

    tx0.addOutput( new bsv.Transaction.Output( {
      script: newTokenScript,
      satoshis: holderSatoshi
    } ) )

    const changeTokenAuthCount = 0
    const changeTokenSupply = 0

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

    // 
    const sig = signTx( tx0, ownerPrivKey, prevLockingScript, inputSatoshis, 0, sighashType )

    const prevOutput = ''

    const transferFn = token.transfer( new Sig( toHex( sig ) ), new PubKey( toHex( ownerPubKey ) ), new Ripemd160( toHex( toAddress.hashBuffer ) ), new Int( newTokenSupply ), new Ripemd160( toHex( changeAddress.hashBuffer ) ), new Int( changeTokenSupply ), changeSatoshi, holderSatoshi, new Bytes(prevOutput), preimage, rabinSigs, paddingBytes )

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

  it( 'change satoshi is zero, 1-1', () => {
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

    const ownerSupply = 1000
    // codePart + OP_RETURN + TOKEN_BRFC_ID(6bytes) + contractId(32bytes) + count(1byte) + ownerPkh(20bytes) + tokenAmount(32bytes) = 91bytes(5b)
    const tokenData = num2bin( 0, 1 ) + toHex( ownerAddress.hashBuffer ) + num2bin( ownerSupply, 32 )
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

    // 
    //  UTXO Token LockingScript
    // codePart + OP_RETURN + TOKEN_BRFC_ID(6bytes) + contractId(32bytes) + prevOutpoint(36bytes) + ownerPkh(20bytes) + tokenAmount(32bytes) = 126bytes(7e)
    const newTokenAuthCount = 0
    const newTokenSupply = 1000
    const newTokenData = num2bin( newTokenAuthCount, 1 ) + toHex( toAddress.hashBuffer ) + num2bin( newTokenSupply, 32 )
    const newTokenLockingScript = lockingBodyScript + ' ' + newTokenData
    const newTokenScript = bsv.Script.fromASM( newTokenLockingScript )

    tx0.addOutput( new bsv.Transaction.Output( {
      script: newTokenScript,
      satoshis: holderSatoshi
    } ) )

    const changeTokenAuthCount = 0
    const changeTokenSupply = 0

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
    const prevOutput = ''

    const transferFn = token.transfer( new Sig( toHex( sig ) ), new PubKey( toHex( ownerPubKey ) ), new Ripemd160( toHex( toAddress.hashBuffer ) ), new Int( newTokenSupply ), new Ripemd160( toHex( changeAddress.hashBuffer ) ), new Int( changeTokenSupply ), changeSatoshi, holderSatoshi, new Bytes(prevOutput), preimage, rabinSigs, paddingBytes )

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

  it( 'Transfer 1-2 with preOutput', () => {
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

    const ownerSupply = 1000
    // codePart + OP_RETURN + TOKEN_BRFC_ID(6bytes) + contractId(32bytes) + count(1byte) + ownerPkh(20bytes) + tokenAmount(32bytes) = 91bytes(5b)
    const tokenData = num2bin( 0, 1 ) + toHex( ownerAddress.hashBuffer ) + num2bin( ownerSupply, 32 )
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

    // 
    const prevScript = bsv.Script.buildPublicKeyHashOut( ownerAddress )
    const prevSatoshi = 5000
    tx0.addOutput( new bsv.Transaction.Output( {
      script: prevScript,
      satoshis: prevSatoshi
    } ) )

    // 
    const prevOutput = tx0.outputs[0].toBufferWriter().toBuffer().toString('hex')
    console.log(prevOutput)

    // 
    //  UTXO Token LockingScript
    // codePart + OP_RETURN + TOKEN_BRFC_ID(6bytes) + contractId(32bytes) + prevOutpoint(36bytes) + ownerPkh(20bytes) + tokenAmount(32bytes) = 126bytes(7e)
    const newTokenAuthCount = 0
    const newTokenSupply = 700
    const newTokenData = num2bin( newTokenAuthCount, 1 ) + toHex( toAddress.hashBuffer ) + num2bin( newTokenSupply, 32 )
    const newTokenLockingScript = lockingBodyScript + ' ' + newTokenData
    const newTokenScript = bsv.Script.fromASM( newTokenLockingScript )

    tx0.addOutput( new bsv.Transaction.Output( {
      script: newTokenScript,
      satoshis: holderSatoshi
    } ) )

    const changeTokenAuthCount = 0
    const changeTokenSupply = 300
    const changeTokenData = num2bin( changeTokenAuthCount, 1 ) + toHex( changeAddress.hashBuffer ) + num2bin( changeTokenSupply, 32 )
    const changeTokenLockingScript = lockingBodyScript + ' ' + changeTokenData
    console.log(changeTokenLockingScript)
    const changeTokenScript = bsv.Script.fromASM( changeTokenLockingScript )

    tx0.addOutput( new bsv.Transaction.Output( {
      script: changeTokenScript,
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

    const transferFn = token.transfer( new Sig( toHex( sig ) ), new PubKey( toHex( ownerPubKey ) ), new Ripemd160( toHex( toAddress.hashBuffer ) ), new Int( newTokenSupply ), new Ripemd160( toHex( changeAddress.hashBuffer ) ), new Int( changeTokenSupply ), changeSatoshi, holderSatoshi, new Bytes(prevOutput), preimage, rabinSigs, paddingBytes )

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

  it( 'Transfer n-2', () => {
    const sighashType = Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID

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

    const ownerSupply = 1000
    // codePart + OP_RETURN + TOKEN_BRFC_ID(6bytes) + contractId(32bytes) + authCount(1byte) + ownerPkh(20bytes) + tokenAmount(32bytes) = 91bytes(5b)
    const tokenData = num2bin( 0, 1 ) + toHex( ownerAddress.hashBuffer ) + num2bin( ownerSupply, 32 )
    token.setDataPart(tokenData)
    console.log( token )

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
    const tx0 = bsv.Transaction.shallowCopy( tx )

    const indexBase = tx0.inputs.length
    console.log(indexBase)

    tokenUtxos.forEach( ( utxo, index ) => {
      console.log(utxo)
      const data = num2bin( 0, 1 ) + toHex( ownerAddress.hashBuffer ) + num2bin( ownerSupply, 32 )

      const lockingScript = lockingBodyScript + ' ' + data
      tx0.addInput(new bsv.Transaction.Input({
        prevTxId: utxo.prevTxId,
        outputIndex: utxo.outputIndex,
        script: ''
      }), bsv.Script.fromASM(lockingScript), holderSatoshi)
      // 
      tx0.inputs[ indexBase + index ].setScript( Buffer.alloc(3000) )
    })

    // 
    //  UTXO Token LockingScript
    // codePart + OP_RETURN + TOKEN_BRFC_ID(6bytes) + contractId(32bytes) + prevOutpoint(36bytes) + ownerPkh(20bytes) + tokenAmount(32bytes) = 126bytes(7e)
    const newTokenAuthCount = 0
    const newTokenSupply = tokenUtxos.length * ownerSupply - 300
    const newTokenData = num2bin( newTokenAuthCount, 1 ) + toHex( toAddress.hashBuffer ) + num2bin( newTokenSupply, 32 )
    const newTokenLockingScript = lockingBodyScript + ' ' + newTokenData
    const newTokenScript = bsv.Script.fromASM( newTokenLockingScript )

    tx0.addOutput( new bsv.Transaction.Output( {
      script: newTokenScript,
      satoshis: holderSatoshi
    } ) )

    const changeTokenAuthCount = 0
    const changeTokenSupply = 300
    const changeTokenData = num2bin( changeTokenAuthCount, 1 ) + toHex( changeAddress.hashBuffer ) + num2bin( changeTokenSupply, 32 )
    const changeTokenLockingScript = lockingBodyScript + ' ' + changeTokenData
    // console.log(changeTokenLockingScript)
    const changeTokenScript = bsv.Script.fromASM( changeTokenLockingScript )

    tx0.addOutput( new bsv.Transaction.Output( {
      script: changeTokenScript,
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

    tokenUtxos.forEach( ( utxo, index ) => {
      const data = num2bin( 0, 1 ) + toHex( ownerAddress.hashBuffer ) + num2bin( ownerSupply, 32 )
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

      // 
      const sig = signTx( tx0, ownerPrivKey, prevLockingScript, holderSatoshi, indexBase + index, sighashType )

      const transferFn = token.transfer( new Sig( toHex( sig ) ), new PubKey( toHex( ownerPubKey ) ), new Ripemd160( toHex( toAddress.hashBuffer ) ), new Int( newTokenSupply ), new Ripemd160( toHex( changeAddress.hashBuffer ) ), new Int( changeTokenSupply ), changeSatoshi, holderSatoshi, new Bytes(''), preimage, rabinSigs, paddingBytes )

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
  } )
} )
