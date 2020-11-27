// rabin auth API
const console = require( 'tracer' ).colorConsole()

const { bsv, num2bin } = require( 'scryptlib' )

const {
  sign
} = require( 'rabinsig' )

class RabinAuth {
  constructor (rabin) {
    this._rabin = rabin
  }

  get pubKey () {
    return BigInt( this._rabin.public )
  }

  sale (order) {
    const contractId = order.contractId
    const buyerPKH = order.buyerPKH
    let tokenAmount = order.tokenAmount
    const sellerPKH = order.sellerPKH // Mock
    let satoshiAmount = order.saotoshiAmount
    const price = 1000 // 1000saotoshi/token

    if (tokenAmount) {
      satoshiAmount = tokenAmount * price
    } else if (satoshiAmount) {
      tokenAmount = satoshiAmount / price
    }

    const msg = order.outpoint + contractId + buyerPKH + num2bin(tokenAmount, 32) + sellerPKH + num2bin(satoshiAmount, 8)

    console.log(msg)

    const signedResult = sign(msg, BigInt( this._rabin.private.p ), BigInt( this._rabin.private.q ), BigInt( this._rabin.public ))
    return {
      order: {
        contractId,
        buyerPKH,
        tokenAmount,
        sellerPKH,
        satoshiAmount,
        price
      },
      signature: signedResult.signature,
      paddingBytes: '00'.repeat(signedResult.paddingByteCount)
    }
  }

  swap (order) {
    const msg = order.outpoint + order.contractIdA + order.buyerPKH + num2bin(order.tokenA_Amount, 32) + order.contractIdB + order.sellerPKH + num2bin(order.tokenB_Amount, 32) + num2bin(order.changeTokenB_Amount, 32)

    console.log(msg)

    try {
      const signedResult = sign(msg, BigInt( this._rabin.private.p ), BigInt( this._rabin.private.q ), BigInt( this._rabin.public ))

      console.log(signedResult)

      return {
        order: order,
        signature: signedResult.signature,
        paddingBytes: '00'.repeat(signedResult.paddingByteCount)
      }
    } catch (e) {
      console.error(e)
    }
  }

  authIssue (msg) {
    const signedResult = sign(msg.outpoint, BigInt( this._rabin.private.p ), BigInt( this._rabin.private.q ), BigInt( this._rabin.public ))
    return {
      signature: signedResult.signature,
      paddingBytes: '00'.repeat(signedResult.paddingByteCount)
    }
  }

  authTransfer (msg) {
    const signedResult = sign(msg.outpoint, BigInt( this._rabin.private.p ), BigInt( this._rabin.private.q ), BigInt( this._rabin.public ))
    return {
      signature: signedResult.signature,
      paddingBytes: '00'.repeat(signedResult.paddingByteCount)
    }
  }
}

// witness list
const witness0 = new RabinAuth(require( './rabin0.json' ))
const witness1 = new RabinAuth(require( './rabin1.json' ))
const witness2 = new RabinAuth(require( './rabin2.json' ))

const map = new Map()
map.set(witness0.pubKey, witness0)
map.set(witness1.pubKey, witness1)
map.set(witness2.pubKey, witness2)

const getWitnessByPubKey = (pubKey) => {
  return map.get(BigInt(pubKey))
}

export { witness0, witness1, witness2, getWitnessByPubKey }
