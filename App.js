import React      from 'react'
import RNSecureKeyStore  from 'react-native-secure-key-store'

import * as ec    from 'react-native-ecc'

import parse      from 'url-parse'
import { Buffer } from 'buffer'

import TouchID from 'react-native-touch-id'

ec.setServiceID('education.assembly')

import {
  StyleSheet,
  Text,
  View,
  Vibration
} from 'react-native'

import {
  RSA,
  RSAKeychain
} from 'react-native-rsa-native'

import Camera from 'react-native-camera'

const PUBLIC_KEY  = 'ASSEMBLY_PUBLIC'

const base64Encode = (input) => {
  var buffer = new Buffer(input)
  var encoded = buffer.toString('base64')
  return encoded
}

class Crypto {

  // public

  async init() {
    const key = await this.loadPublicKey()

    if (key) {
      console.debug('Found existing key')
      return
    }

    console.debug('No key found')
    const newKey = await this.createKey()
    await this.persistPublicKey(newKey.pub)
  }

  async sign(data) {
    console.debug('Signing value')
    const publicKey = await this.loadPublicKey()
    const key = await this.loadSigningKey(publicKey)
    if (!key) {
      console.error('Cannot sign, key is null')
    }

    return new Promise((resolve) => {
      key.sign({
        data,
        algorithm: 'sha256'
      }, (err, sig) => {
        if (err) {
          console.log(err)
        }
        resolve(sig)
      })
    })
  }

  // private

  loadSigningKey(publicKey) {
    console.debug('Attempting to load signing key')
    return new Promise((resolve) => {
      ec.lookupKey(publicKey, (err, key) => {
        if (err) {
          console.error(err)
        }
        resolve(key)
      })
    })
  }

  loadPublicKey() {
    console.debug('Attempting to load public key')
    return new Promise((resolve) => {
      RNSecureKeyStore.get(PUBLIC_KEY)
        .then((result) => {
          const resultBuffer = Buffer.from(result, 'base64')
          resolve(new Buffer(resultBuffer))
        }, (err) => {
          resolve(null)
        })
      })
  }

  persistPublicKey(publicKey) {
    console.debug('Persisting public key')
    return new Promise((resolve) => {
      RNSecureKeyStore.set(PUBLIC_KEY, publicKey.toString('base64'))
        .then((result) => {
          resolve(result)
        })
      })
  }

  createKey() {
    console.debug('Generating a new key pair')
    return new Promise((resolve) => {
      ec.keyPair('secp256r1', (err, key) => {
        if (err) {
          console.error(err)
        }
        console.log(key)
        resolve(key)
      })
    })
  }
}


class AuthService {
  constructor(url) {
    this.url = url
  }

  async login(url) {
    const payload = await this.payload()
    await this.postPayload(payload)
  }

  async payload(url) {
    const callback = `https://${url.host}${url.pathname}`
    console.debug(`Calling ${callback}`)

    const crypto = new Crypto()

    const publicKey = await crypto.loadPublicKey()
    const key = await crypto.loadSigningKey(publicKey)

    const identity = key.pub.toString('hex')

    const server = url.toString()

    const client = JSON.stringify({
      ver: 1,
      idk: identity
    })

    const clientData = base64Encode(client)
    const serverData = base64Encode(server)

    const valueToSign = clientData + serverData

    const ids = await crypto.sign(valueToSign)
    const idsData = ids.toString('base64')

    const payload = {
      client: clientData,
      server: serverData,
      ids:    idsData
    }

    return payload
  }

  postPayload(payload) {
    return fetch(callback, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload)
    })
  }
}

export default class App extends React.Component {
  constructor() {
    super()
    this.state = {
      requesting: false,
      authenticated: false
    }
  }

  async componentDidMount() {
    // const result = await TouchID.authenticate('Touch to continue')

    // if (!result) {
    //   return
    // }

    const crypto = new Crypto()
    await crypto.init()
    this.setState({ ...this.state, authenticated: true })
  }

  serverCallback = async (url) => {
    this.setState({ requesting: true })

    const authService = new AuthService(url)
    const result = await authService.login()
    console.log(result)
    this.setState({ ...state, requesting: false })
  }

  onBarCodeRead = (e) => {
    if (!this.state.requesting) {
      Vibration.vibrate()
      const url = parse(e.data, true)
      this.serverCallback(url)
    }
  }

  render() {
    return (
      <View style={styles.container}>
        {this.state.authenticated &&
          <Camera
            ref={(cam) => {
              this.camera = cam
            }}
            onBarCodeRead={this.onBarCodeRead}
            style={styles.preview}
            aspect={Camera.constants.Aspect.fill}
          />
        }
      </View>
    )
  }
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    flexDirection: 'row',
  },
  preview: {
    flex: 1,
    justifyContent: 'flex-end',
    alignItems: 'center'
  }
})
