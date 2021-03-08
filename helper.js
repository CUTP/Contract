const path = require( 'path' )

const {
  bsv,
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
/**
 * 计算目前tx所需要的充值费用
 * @param {*} tx
 */
function calcChargeFee (tx, feePerKb = 500) {
  // 计算所需的费用
  // 所有输出的satoshis之和，所有输入的satoshi之和，判断交易的大小
  // console.log( 'Pre-Transaction Size', tx0._estimateFee() )
  // 根据txSize计算所需的手续费
  // feePerKb = 500
  tx.feePerKb(feePerKb)
  // 通过size计算出的费用 - (所有输入-所有输出) + 一个P2PKH交易的大小
  return tx._estimateFee() - tx._getUnspentValue() + Math.ceil(149 / 1000 * (feePerKb))
}
/**
 * Charge satoshis to Contract Tx
 * @param {*} p2pkhUtxos
 * @param {*} chargeAmount
 */
function buildChargeTx ( p2pkhUtxos, privKeys, chargeAddressStr, chargeAmount, changeAddressStr, feePerKb = 500) {
  const tx = new bsv.Transaction()
  tx.from(p2pkhUtxos)
  tx.feePerKb(feePerKb)
  tx.addOutput( new bsv.Transaction.Output( {
    script: bsv.Script.buildPublicKeyHashOut( chargeAddressStr ),
    satoshis: chargeAmount
  } ) )
  tx.change(changeAddressStr)
  tx.sign(privKeys)
  return tx
}

function loadTokenContractDesc ( fileName ) {
  const contract = require(`./out/${fileName}`)
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
  Burn: 4700
}

const CONTRACT_BRFC_ID = '99b1e6a59ced'
const BATON_BRFC_ID = 'cc854318d187'
const TOKEN_BRFC_ID = '460a852aa0ea'
const SALE_BRFC_ID = 'accb4bd81142'
const SWAP_BRFC_ID = '1400fef15095'

const NFT_CONTRACT_BRFC_ID = 'dacdd94bfb3e'
const NFT_BATON_BRFC_ID = '5a3a78b9b744'
const NFT_FACTORY_BRFC_ID = 'd8663d0d0ef4'
const NFT_TOKEN_BRFC_ID = 'e22200618383'
const NFT_CERT_BRFC_ID = 'c7f0eab6f355'
const NFT_SALE_BRFC_ID = 'a2d7f217c2c0'
const NFT_SWAP_BRFC_ID = '35a30d90364c'

const genesisSchema = {
  name: 'string',
  symbol: 'string',
  issuer: 'string',
  domain: 'string',
  rule: 'number',
  decimals: 'number',
  brfc: 'bytes'
}

const batonSchema = {
  supply: 'bytes',
  issuerPKH: 'bytes',
  brfc: 'bytes'
}

const tokenSchema = {
  amount: 'bytes', // fixed 32bytes number
  authCount: 'number',
  holderPKH: 'bytes',
  brfc: 'bytes'
}

// Notify Satoshi amount
const NOTIFY_SATOSHI = 546

// Token Value的字节数，32字节，256bit, uint256
const TokenValueLen = 32

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
  outputs2Hex,
  string2Hex,
  hex2String,
  sleep,

  calcChargeFee,
  buildChargeTx,

  loadTokenContractDesc,

  CONTRACT_BRFC_ID,
  BATON_BRFC_ID,
  TOKEN_BRFC_ID,
  SALE_BRFC_ID,
  SWAP_BRFC_ID,

  NFT_CONTRACT_BRFC_ID,
  NFT_BATON_BRFC_ID,
  NFT_FACTORY_BRFC_ID,
  NFT_TOKEN_BRFC_ID,
  NFT_CERT_BRFC_ID,
  NFT_SALE_BRFC_ID,
  NFT_SWAP_BRFC_ID,

  NOTIFY_SATOSHI,
  TokenValueLen,

  changTxForMSB,

  UnlockingScriptSize,

  genesisSchema,
  batonSchema,
  tokenSchema
}
