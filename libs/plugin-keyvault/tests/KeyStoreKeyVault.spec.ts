/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { ClientSecretCredential } from '@azure/identity';
import { CryptographicKey, IKeyContainer, KeyContainer } from 'verifiablecredentials-crypto-sdk-typescript-keys';
import { Subtle, CryptoFactory } from 'verifiablecredentials-crypto-sdk-typescript-plugin';
import KeyStoreKeyVault from '../src/keyStore/KeyStoreKeyVault';
import KeyVaultEcdsaProvider from '../src/plugin/KeyVaultEcdsaProvider';
import { KeyStoreOptions, KeyStoreInMemory, KeyReference } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import { KeyClient } from '@azure/keyvault-keys';
import { SecretClient } from '@azure/keyvault-secrets';
import { CryptoKey } from 'webcrypto-core';
import Credentials from './Credentials';

// Sample config
const tenantId = Credentials.tenantGuid;
const clientId = Credentials.clientId;
const clientSecret = encodeURI(Credentials.clientSecret);
const vaultUri = Credentials.vaultUri;
const keyVaultEnable = vaultUri.startsWith('https://');

const subtle: Subtle = new Subtle();

const logging = require('adal-node').Logging;
logging.setLoggingOptions({
  log: (_level: any, _message: any, _error: any) => {
    // provide your own implementation of the log function
    // console.log(`${level}, ${message}, ${error}`);
  },
  level: logging.LOGGING_LEVEL.INFO, // provide the logging level
  loggingWithPII: true  // Determine if you want to log personal identification information. The default value is false.
});

let originalTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
beforeEach(async () => {
  jasmine.DEFAULT_TIMEOUT_INTERVAL = 60000;
});

afterEach(() => {
  jasmine.DEFAULT_TIMEOUT_INTERVAL = originalTimeout;
});

describe('KeyStoreKeyVault', () => {
  const alg = { name: 'ECDSA', namedCurve: 'SECP256K1', hash: { name: 'SHA-256' } };
  if (!keyVaultEnable) {
    console.log('Key vault is enabled. Add your credentials to Credentials.ts')
    return;
  }

  it('should list a named generated key', async () => {
    const name = 'KvTest-KeyStoreKeyVault' + Math.random().toString(10).substr(2);
    const cache = new KeyStoreInMemory();
    const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
    const keyStore = new KeyStoreKeyVault(credential, vaultUri, cache);
    try {
      const provider = new KeyVaultEcdsaProvider(subtle, keyStore);
      await provider.onGenerateKey(alg, false, ['sign'], { keyReference: new KeyReference(name) });
      let list = await keyStore.list('key', new KeyStoreOptions({ latestVersion: false }));
      expect(list[name]).toBeDefined();
      const key = await keyStore.get(new KeyReference(name, 'key'), new KeyStoreOptions({ latestVersion: false }));
      expect(key).toBeDefined();
      expect((await cache.list())[name]).toBeDefined();
    } finally {
      await (<KeyClient>keyStore.getKeyStoreClient('key')).beginDeleteKey(name);
    }
  });

  it('should list a specific version of the key', async () => {
    const name = 'KvTest-KeyStoreKeyVault' + Math.random().toString(10).substr(2);
    const cache = new KeyStoreInMemory();
    const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
    const keyStore = new KeyStoreKeyVault(credential, vaultUri, cache);
    try {
      const provider = new KeyVaultEcdsaProvider(subtle, keyStore);
      // generate two keys 
      const keyPair = await provider.onGenerateKey(alg, false, ['sign'], { keyReference: new KeyReference(name) });
      await provider.onGenerateKey(alg, false, ['sign'], { keyReference: new KeyReference(name) });

      let parts = (<any>keyPair.publicKey.algorithm).kid.split('/');
      const keyName = `${parts[parts.length-2]}/${parts[parts.length-1]}`;

      let list = await keyStore.list('key', new KeyStoreOptions({ latestVersion: false }));
      expect(list[name].kids[0].includes(keyName) || list[name].kids[1].includes(keyName)).toBeTruthy();
      const key = await keyStore.get(new KeyReference(name, 'key',keyName), new KeyStoreOptions({ latestVersion: false }));
      expect(key.keys.length).toEqual(1);
      console.log(`name: ${keyName}`);
      console.log(`${JSON.stringify(key.keys[0])}`);
      const kidParts = key.keys[0].kid.split('/');
      expect(parts[parts.length - 1]).toEqual(kidParts[kidParts.length - 1]);
      expect((await cache.list())[name]).toBeDefined();
    } finally {
      await (<KeyClient>keyStore.getKeyStoreClient('key')).beginDeleteKey(name);
    }
  });
  it('should list a default generated key', async () => {
    const name = 'ECDSA-sign-EC';
    const cache = new KeyStoreInMemory();
    const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
    const keyStore = new KeyStoreKeyVault(credential, vaultUri, cache);
    let list = await keyStore.list('key', new KeyStoreOptions({ latestVersion: false }));
    let versionsCount = list[name] ? list[name].kids.length + 1 : 1;
    try {
      const provider = new KeyVaultEcdsaProvider(subtle, keyStore);
      await provider.onGenerateKey(alg, false, ['sign'], { keyReference: new KeyReference(name) });
      let list = await keyStore.list('key', new KeyStoreOptions({ latestVersion: false }));
      expect(list[name].kids.length).toEqual(versionsCount);
    } finally {
      await (<KeyClient>keyStore.getKeyStoreClient('key')).beginDeleteKey(name);
    }
  });
  it('should set a secret', async () => {
    const name = 'KvTest-KeyStoreKeyVault' + Math.random().toString(10).substr(2);
    const cache = new KeyStoreInMemory();
    const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
    const keyStore = new KeyStoreKeyVault(credential, vaultUri, cache);
    let throwed = false;
    try {
      await keyStore.save(new KeyReference(name, 'secret'), 'abcdefg');
      let list = await keyStore.list('secret', new KeyStoreOptions({ latestVersion: false }));
      expect(list[name]).toBeDefined();
      await cache.get(new KeyReference(name, 'secret'));
      expect(throwed).toBeTruthy();
    } catch (err) {
      throwed = true;
      expect(err.message).toEqual(`${name} not found`)

    } finally {
      await (<SecretClient>keyStore.getKeyStoreClient('secret')).beginDeleteSecret(name);
    }
  });

  it('should return an RSA key container as a secret', async () => {
    const name = 'KvTest-KeyStoreKeyVault' + Math.random().toString(10).substr(2);
    const cache = new KeyStoreInMemory();
    const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
    const keyStore = new KeyStoreKeyVault(credential, vaultUri, cache);
    try {
      const alg = { name: 'RSA-OAEP', hash: 'SHA-256', modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]) };

      const cryptoKey: any = <CryptoKey>await subtle.generateKey(alg, true, ['encrypt']);
      const jwk: any = await subtle.exportKey('jwk', cryptoKey.privateKey);
      jwk.kid = name;
      await keyStore.save(new KeyReference(name, 'secret'), <CryptographicKey>jwk, new KeyStoreOptions());
      let container: IKeyContainer = await keyStore.get(new KeyReference(name, 'secret'), new KeyStoreOptions({ latestVersion: false }));
      expect(container.keys.length).toEqual(1);
      expect(container.keys[0].kty).toEqual('RSA');
      expect((await cache.list())[name]).toBeDefined();

    } finally {
      await (<SecretClient>keyStore.getKeyStoreClient('secret')).beginDeleteSecret(name);
    }
  });

  it('should return an OKP key container as a secret', async () => {
    const name = 'KvTest-KeyStoreKeyVault' + Math.random().toString(10).substr(2);
    const cache = new KeyStoreInMemory();
    const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
    const keyStore = new KeyStoreKeyVault(credential, vaultUri, cache);
    try {
      const alg = { name: 'EcDSA', namedCurve: 'K-256', hash: { name: 'SHA-256' } };

      const cryptoKey: any = <CryptoKey>await subtle.generateKey(alg, true, ['sign']);
      const jwk: any = await subtle.exportKey('jwk', cryptoKey.privateKey);
      jwk.kid = name;
      jwk.kty = 'OKP';
      await keyStore.save(new KeyReference(name, 'secret'), <CryptographicKey>jwk, new KeyStoreOptions());
      let container = await keyStore.get(new KeyReference(name, 'secret'), new KeyStoreOptions({ latestVersion: false }));
      expect(container.keys.length).toEqual(1);
      expect(container.keys[0].kty).toEqual('OKP');
      expect((await cache.list())[name]).toBeDefined();

    } finally {
      await (<SecretClient>keyStore.getKeyStoreClient('secret')).beginDeleteSecret(name);
    }
  });

  it('should import a non extractable key', async () => {
    const name = 'KvTest-KeyStoreKeyVault' + Math.random().toString(10).substr(2);
    const cache = new KeyStoreInMemory();
    const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
    const keyStore = new KeyStoreKeyVault(credential, vaultUri, cache);

    try {
      const alg = <any>{
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: "SHA-256" }
      }

      const keyReference = new KeyReference(name, 'key');
      const plugin = new KeyVaultEcdsaProvider(subtle, keyStore);

      const cryptoKey: any = <CryptoKey>await subtle.generateKey(alg, true, ['sign'], { keyReference: new KeyReference(name) });
      const jwk: any = await subtle.exportKey('jwk', cryptoKey.privateKey);
      jwk.kid = name;


      await keyStore.save(keyReference, jwk, new KeyStoreOptions());
      let container = await keyStore.get(keyReference, new KeyStoreOptions({ latestVersion: false }));
      expect(container.keys.length).toEqual(1);
      expect((await cache.list())[name]).toBeDefined();
    } finally {
      await (<KeyClient>keyStore.getKeyStoreClient('key')).beginDeleteKey(name);
    }
  });
});

describe('KeyStoreKeyVault without credentials', () => {
  it('should convert toKeyVaultKey', async () => {
    const subtle = new Subtle();
    let cryptokey = <CryptoKeyPair>await subtle.generateKey(
      <any>{
        name: "ECDSA",
        namedCurve: "K-256",
      },
      true,
      ["sign", "verify"]);
    let key = await subtle.exportKey('jwk', cryptokey.privateKey);

    let kvKey = KeyStoreKeyVault.toKeyVaultKey(<any>key);
    expect(kvKey).toBeDefined();

    cryptokey = <CryptoKeyPair>await subtle.generateKey(
      <any>{
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: "SHA-256" }
      },
      true,
      ["sign", "verify"]);

    key = await subtle.exportKey('jwk', cryptokey.privateKey);
    kvKey = KeyStoreKeyVault.toKeyVaultKey(<any>key);
    expect(kvKey).toBeDefined();
  });
});
