const path = require( 'path' )

const {
  bsv,
  compile,
  getPreimage,
  toHex
} = require( 'scryptlib' )

const BN = bsv.crypto.BN

// reverse hexStr byte order
function reverseEndian ( hexStr ) {
  const num = new BN( hexStr, 'hex' )
  const buf = num.toBuffer()
  return buf.toString( 'hex' ).match( /.{2}/g ).reverse().join( '' )
}

function unlockP2PKHInput ( privateKey, tx, inputIndex, sigtype ) {
  const sig = new bsv.Transaction.Signature( {
    publicKey: privateKey.publicKey,
    prevTxId: tx.inputs[ inputIndex ].prevTxId,
    outputIndex: tx.inputs[ inputIndex ].outputIndex,
    inputIndex,
    signature: bsv.Transaction.Sighash.sign( tx, privateKey, sigtype,
      inputIndex,
      tx.inputs[ inputIndex ].output.script,
      tx.inputs[ inputIndex ].output.satoshisBN ),
    sigtype
  } )

  tx.inputs[ inputIndex ].setScript( bsv.Script.buildPublicKeyHashIn(
    sig.publicKey,
    sig.signature.toDER(),
    sig.sigtype
  ) )
}

function compileContract ( fileName ) {
  const filePath = path.join( __dirname, 'contracts', fileName )
  console.log( `Compiling contract ${filePath} ...` )

  const result = compile(
    { path: filePath },
    { desc: true, outputDir: path.join( __dirname, 'autoGen' ) }
  )

  if ( result.errors.length > 0 ) {
    console.log( `Contract ${filePath} compiling failed with errors:` )
    console.log( result.errors )
    throw result.errors
  }
  console.log( `Compiling Finished ${filePath} ...` )

  return result
}

function loadTokenContractDesc ( fileName ) {
  const contract = require(`./autoGen/${fileName}`)
  return contract
}

function outputs2Hex ( ...outputs ) {
  const writer = new bsv.encoding.BufferWriter()
  outputs.forEach( output => {
    output.toBufferWriter( writer )
  } )
  const buf = writer.toBuffer()
  return buf.toString( 'hex' )
}

function string2Hex ( utf8str, size ) {
  const buf = Buffer.alloc( size, utf8str.padEnd( size, ' ' ), 'utf8' )
  return buf.toString( 'hex' )
}

function hex2String ( hex ) {
  const buf = Buffer.from( hex, 'hex' )
  return buf.toString( 'utf8' ).trim()
}

const sleep = ( ms ) => new Promise( ( resolve, _ ) => setTimeout( () => resolve(), ms ) )

const UnlockingScriptSize = {
  Initiate: 8016,
  Issue: 8090,
  Transfer: 8100,
  Split: 8128,
  Burn: 7967
}

const CONTRACT_BRFC_ID = 'b02de8c88330'
const BATON_BRFC_ID = '95c087f2c67c'
const TOKEN_BRFC_ID = 'd0d555f9d6d4'
const SALE_BRFC_ID = '4c3b48a0651e'
const SWAP_BRFC_ID = '520d125f21e7'

const NFT_CONTRACT_BRFC_ID = 'dacdd94bfb3e'
const NFT_BATON_BRFC_ID = '5a3a78b9b744'
const NFT_TOKEN_BRFC_ID = 'e22200618383'
const NFT_SALE_BRFC_ID = 'a2d7f217c2c0'
const NFT_SWAP_BRFC_ID = '35a30d90364c'

// Notify Satoshi amount
const NOTIFY_SATOSHI = 546

// Token Value的字节数，32字节，256bit, uint256
const TokenValueLen = 32

// Converts a number into a sign-magnitude representation of certain size as a string
// Throws if the number cannot be accommodated
// Often used to append numbers to OP_RETURN, which are read in contracts
// Support Bigint
function num2bin (n, dataLen) {
  const num = new BN(n)
  if (num.eqn(0)) {
    return '00'.repeat(dataLen)
  }
  const s = num.toSM({ endian: 'little' }).toString('hex')

  const byteLen_ = s.length / 2
  if (byteLen_ > dataLen) {
    throw new Error(`${n} cannot fit in ${dataLen} byte[s]`)
  }
  if (byteLen_ === dataLen) {
    return s
  }

  const paddingLen = dataLen - byteLen_
  const lastByte = s.substring(s.length - 2)
  const rest = s.substring(0, s.length - 2)
  let m = parseInt(lastByte, 16)
  if (num.isNeg) {
    // reset sign bit
    m &= 0x7F
  }
  let mHex = m.toString(16)
  if (mHex.length < 2) {
    mHex = '0' + mHex
  }

  const padding = n > 0 ? '00'.repeat(paddingLen) : '00'.repeat(paddingLen - 1) + '80'
  return rest + mHex + padding
}

// Support Bigint
function bin2num (s) {
  const hex = s.toString('hex')
  const lastByte = hex.substring(hex.length - 2)
  const rest = hex.substring(0, hex.length - 2)
  const m = parseInt(lastByte, 16)
  const n = m & 0x7F
  let nHex = n.toString(16)
  if (nHex.length < 2) {
    nHex = '0' + nHex
  }
  // Support negative number
  let bn = BN.fromHex(rest + nHex, { endian: 'little' } )
  if (m >> 7) {
    bn = bn.neg()
  }
  return BigInt(bn)
}

function changTxForMSB (tx_, inputLockingScriptASM, inputAmount, inputIndex, sighashType) {
  const MSB_THRESHOLD = 0x7e
  const sha256d = bsv.crypto.Hash.sha256sha256
  const n = tx_.nLockTime

  for (let i = n; ; i++) {
  // malleate tx and thus sighash to satisfy constraint
    tx_.nLockTime = i
    const preimage_ = getPreimage(tx_, inputLockingScriptASM, inputAmount, inputIndex, sighashType)
    const preimage = toHex(preimage_)
    const h = sha256d(Buffer.from(preimage, 'hex'))
    const msb = h.readUInt8()
    if (msb < MSB_THRESHOLD) {
      // the resulting MSB of sighash must be less than the threshold
      break
    }
  }
}

module.exports = {
  reverseEndian,
  unlockP2PKHInput,
  compileContract,
  outputs2Hex,
  string2Hex,
  hex2String,
  sleep,

  loadTokenContractDesc,

  CONTRACT_BRFC_ID,
  BATON_BRFC_ID,
  TOKEN_BRFC_ID,
  SALE_BRFC_ID,
  SWAP_BRFC_ID,

  NFT_CONTRACT_BRFC_ID,
  NFT_BATON_BRFC_ID,
  NFT_TOKEN_BRFC_ID,
  NFT_SALE_BRFC_ID,
  NFT_SWAP_BRFC_ID,

  NOTIFY_SATOSHI,
  TokenValueLen,

  bin2num,
  num2bin,
  changTxForMSB,

  UnlockingScriptSize
}
