
require( 'mocha' )

const { bsv, buildContractClass, signTx, toHex, getPreimage, Sig, Int, PubKey, Ripemd160, SigHashPreimage, sighashType2Hex, Bytes, serializeState, STATE_LEN_2BYTES, deserializeState, bin2num } = require( 'scryptlib' )

import { expect } from 'chai'

import { witness0, witness1, witness2, getWitnessByPubKey } from './auth.mock'

describe( 'Token Witness', async () => {
  beforeEach( async () => {
  } )

  it( 'witness', async () => {
    console.log(
      witness0.pubKey.toString(16),
      witness1.pubKey.toString(16),
      witness2.pubKey.toString(16)
    )

    const asmVars = {
      pubKeyHash: '0d566dd15bedb12ad31552786b816bb9ced7b8f9',
      'witness[0]': '0',
      'witness[1]': '9dc57241fe6b62bbc1f168f102dbd6dd00d9884b7c1a70e5b11a95a579c5a66427231ebfacdfd99c2ca22d5968d3af920621e8fd99a7fc24c35ee8a2e19fa8d8cbd26d4d294f88ad160298f956528aa760fffe71d01e701e3d080def8ec8d3ad34ed0536c8fef0ac79976d14369091c105a8357df36289360d9dd65b20',
      'witness[2]': 'ad679948534ce8f3b2350d65d77c4a8ecc3a31846f78db9f0bbad4dc3899c96a978efd7a16a00f4d4e5db4a3010f65abc1f8b97c19cd908060c8ba1740cf9819893c871caac231fd9e541769c8d53cd4b9c1fde252b89a1afbbc54c3cae5d4ff323084a5feda161ef508ad02ac0f6a2090cf771107ad3c84780f42bf26',
      'witness[3]': 'e15284f3c688783ddd43dd5750c22e4d75577639de1dc47d73efdb97f9ce53b6555f8e4c70ce7d7d9702c27605b6edf4bd19309073f1436883e870d87525556213d414d54be80600dd9c1e2872b90604da1f898af0a3dbf13ff4e9fe08e8f633a5f3d1eb99ed325da42211d4d249d6a14eda256dc310bddab7e75a444c'
    }

    const witnessList = [
      bin2num(asmVars['witness[0]']),
      bin2num(asmVars['witness[1]']),
      bin2num(asmVars['witness[2]']),
      bin2num(asmVars['witness[3]'])
    ]

    const rabinSigs = [ ]
    const paddingBytes = [ ]

    for (const pubKey of witnessList) {
      const witness = getWitnessByPubKey(pubKey)
      console.log(pubKey, witness)
      if (witness) {
        const sig = witness.authIssue( { outpoint: 'AA' } )
        rabinSigs.push(new Int(sig.signature))
        paddingBytes.push(new Bytes(sig.paddingBytes))
      } else {
        rabinSigs.push(new Int(0))
        paddingBytes.push(new Bytes(''))
      }
    }

    console.log(rabinSigs)
    console.log(paddingBytes)
  } ).timeout( 5000000 )
} )
