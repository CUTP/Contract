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
    title: 'Contract of the Controlled UTXO Fungible Token',
    author: 'LI Long (ChainBow)',
    version: '3',
    expect: '99b1e6a59ced'
  },
  {
    title: 'Baton of the Controlled UTXO Fungible Token',
    author: 'LI Long (ChainBow)',
    version: '3',
    expect: 'cc854318d187'
  },
  {
    title: 'Token of the Controlled UTXO Fungible Token',
    author: 'LI Long (ChainBow)',
    version: '3',
    expect: '460a852aa0ea'
  },
  {
    title: 'Sale of the Controlled UTXO Fungible Token',
    author: 'LI Long (ChainBow)',
    version: '3',
    expect: 'accb4bd81142'
  },
  {
    title: 'Swap of the Controlled UTXO Fungible Token',
    author: 'LI Long (ChainBow)',
    version: '3',
    expect: '1400fef15095'
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
    title: 'Token Factory of the Controlled UTXO Non-Fungible Token',
    author: 'LI Long (ChainBow)',
    version: '1',
    expect: 'd8663d0d0ef4'
  },
  {
    title: 'Token of the Controlled UTXO Non-Fungible Token',
    author: 'LI Long (ChainBow)',
    version: '1',
    expect: 'e22200618383'
  },
  {
    title: 'Token Certificate of the Controlled UTXO Non-Fungible Token',
    author: 'LI Long (ChainBow)',
    version: '1',
    expect: 'c7f0eab6f355'
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
    expect: 'bbf12ab68741'
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
