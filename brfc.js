import { bsv } from 'scryptlib'
import { expect } from 'chai'

const specList = [
  {
    title: 'BRFC Specifications',
    author: 'andy (nChain)',
    version: '1',
    expect: '57dd1f54fc67'
  },
  {
    title: 'bsvalias Payment Addressing (PayTo Protocol Prefix)',
    author: 'andy (nChain)',
    version: '1',
    expect: '74524c4d6274'
  },
  {
    title: 'bsvalias Integration with Simplified Payment Protocol',
    author: 'andy (nChain)',
    version: '1',
    expect: '0036f9b8860f'
  },
  {
    title: 'The Improved UTXO Fungible Token Specifications',
    author: 'LI Long (ChainBow)',
    version: '1',
    expect: 'ca1f6df355e6'
  },
  {
    title: 'Contract of the Improved UTXO Fungible Token',
    author: 'LI Long (ChainBow)',
    version: '1',
    expect: '3638947f96b4'
  },
  {
    title: 'Baton of the Improved UTXO Fungible Token',
    author: 'LI Long (ChainBow)',
    version: '1',
    expect: '8ae7d68e41af'
  },
  {
    title: 'Token of the Improved UTXO Fungible Token',
    author: 'LI Long (ChainBow)',
    version: '1',
    expect: '28466486dbb8'
  },
  {
    title: 'The Improved UTXO Non-Fungible Token Specifications',
    author: 'LI Long (ChainBow)',
    version: '1',
    expect: 'b052da60ca22'
  },
  {
    title: 'Contract of the Improved UTXO Non-Fungible Token',
    author: 'LI Long (ChainBow)',
    version: '1',
    expect: '40fd856ecf73'
  },
  {
    title: 'Baton of the Improved UTXO Non-Fungible Token',
    author: 'LI Long (ChainBow)',
    version: '1',
    expect: '12809647c7f7'
  },
  {
    title: 'Token of the Improved UTXO Non-Fungible Token',
    author: 'LI Long (ChainBow)',
    version: '1',
    expect: '471037cf88fe'
  },
  {
    title: 'Contract of the Controlled UTXO Fungible Token',
    author: 'LI Long (ChainBow)',
    version: '1',
    expect: 'b02de8c88330'
  },
  {
    title: 'Baton of the Controlled UTXO Fungible Token',
    author: 'LI Long (ChainBow)',
    version: '1',
    expect: '95c087f2c67c'
  },
  {
    title: 'Token of the Controlled UTXO Fungible Token',
    author: 'LI Long (ChainBow)',
    version: '1',
    expect: 'd0d555f9d6d4'
  },
  {
    title: 'Sale of the Controlled UTXO Fungible Token',
    author: 'LI Long (ChainBow)',
    version: '1',
    expect: '4c3b48a0651e'
  },
  {
    title: 'Swap of the Controlled UTXO Fungible Token',
    author: 'LI Long (ChainBow)',
    version: '1',
    expect: '520d125f21e7'
  },
  {
    title: 'Contract of the Controlled UTXO Non-Fungible Token',
    author: 'LI Long (ChainBow)',
    version: '1',
    expect: 'dacdd94bfb3e'
  },
  {
    title: 'Baton of the Controlled UTXO Non-Fungible Token',
    author: 'LI Long (ChainBow)',
    version: '1',
    expect: '5a3a78b9b744'
  },
  {
    title: 'Token of the Controlled UTXO Non-Fungible Token',
    author: 'LI Long (ChainBow)',
    version: '1',
    expect: 'e22200618383'
  },
  {
    title: 'Sale of the Controlled UTXO Non-Fungible Token',
    author: 'LI Long (ChainBow)',
    version: '1',
    expect: 'a2d7f217c2c0'
  },
  {
    title: 'Swap of the Controlled UTXO Non-Fungible Token',
    author: 'LI Long (ChainBow)',
    version: '1',
    expect: '35a30d90364c'
  },
  {
    title: 'API of the Controlled UTXO Non-Fungible Token',
    author: 'LI Long (ChainBow)',
    version: '1',
    expect: '35a30d90364c'
  }

]

const createBrfcId = function (spec) {
  const sha256d = bsv.crypto.Hash.sha256sha256
  const hash = sha256d(Buffer.from(
    spec.title.trim() +
    (spec.author || '').trim() +
    (spec.version || '').trim()
  ))
  const bitcoinDisplayHash = hash
    .reverse()
    .toString('hex')
  const brfcId = bitcoinDisplayHash.substring(0, 12)
  if (spec.expect) {
    expect(brfcId).to.equal(spec.expect)
  }
  return brfcId
}

const main = () => {
  specList.forEach(spec => {
    console.log(spec, createBrfcId(spec))
  })
}

main()
