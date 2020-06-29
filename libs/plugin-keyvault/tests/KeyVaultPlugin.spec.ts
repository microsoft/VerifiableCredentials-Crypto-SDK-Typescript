/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { ClientSecretCredential } from '@azure/identity';
import KeyStoreKeyVault from '../src/keyStore/KeyStoreKeyVault';
import KeyVaultEcdsaProvider from '../src/plugin/KeyVaultEcdsaProvider';
import KeyVaultRsaOaepProvider from '../src/plugin/KeyVaultRsaOaepProvider';
import { KeyStoreOptions, KeyStoreInMemory, KeyReference } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import { KeyClient } from '@azure/keyvault-keys';
import { Subtle } from 'verifiablecredentials-crypto-sdk-typescript-plugin';
import Credentials from './Credentials';
const clone = require('clone');

// Sample config
const tenantId = Credentials.tenantGuid;
const clientId = Credentials.clientId;
const clientSecret = encodeURI(Credentials.clientSecret);
const vaultUri = Credentials.vaultUri;

const subtle = new Subtle();
// const random = (length: number) => Math.random().toString(36).substring(length);
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

describe('KeyVaultPlugin', () => {
  const alg = { name: 'ECDSA', namedCurve: 'SECP256K1', hash: { name: 'SHA-256' } };
  it('should generate a key', async () => {
    const name = 'ECDSA-sign-EC';
    const cache = new KeyStoreInMemory();
    const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
    const keyStore = new KeyStoreKeyVault(credential, vaultUri, cache);
    const plugin = new KeyVaultEcdsaProvider(subtle, keyStore);
    try {
      const result: CryptoKeyPair = await plugin.onGenerateKey(alg, false, ['sign']);
      expect((<any>result.publicKey).algorithm.namedCurve).toEqual('K-256');
      expect(result.publicKey.algorithm.name).toEqual('ECDSA');
      expect((<any>result.publicKey.algorithm).kid.startsWith('https')).toBeTruthy();
    } finally {
      await (<KeyClient>keyStore.getKeyStoreClient('key')).beginDeleteKey(name);
    }
  });

  it('should generate a key and secret', async () => {
    const name = 'ECDSA-sign-EC';
    const cache = new KeyStoreInMemory();
    const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
    const keyStore = new KeyStoreKeyVault(credential, vaultUri, cache);
    try {
      let list = await keyStore.list('key', new KeyStoreOptions({ latestVersion: false }));
      const versions = list[name];
      const plugin = new KeyVaultEcdsaProvider(subtle, keyStore);

      // Generate EC
      let keyPair: CryptoKeyPair = await plugin.onGenerateKey(alg, false, ['sign', 'verify']);
      //let jwk = await plugin.onExportKey('jwk', keyPair.publicKey);
      list = await keyStore.list('key', new KeyStoreOptions({ latestVersion: false }));
      // problem: extrable is used to mark secret/key meaning we cannot extract a public key.
      const jwk = (await keyStore.get(new KeyReference(name, 'key'))).getKey();
      if (versions) {
        expect(list[name].kids.length).toEqual(versions.kids.length + 1);
      } else {
        expect(list[name].kids.length).toEqual(1);
      }

      expect(keyPair.publicKey.algorithm.name).toEqual('ECDSA');
      expect(keyPair.publicKey.extractable).toEqual(true);
      expect(keyPair.publicKey.type).toEqual('public');
      expect(keyPair.publicKey.usages).toEqual(['sign', 'verify']);
      let container = await keyStore.get(new KeyReference(name, 'key'), new KeyStoreOptions({ latestVersion: false }));
      expect(container.keys.length).toEqual(1);

      // Add new version
      (<any>jwk).kid = '#key2';
      keyPair = await plugin.onGenerateKey(alg, false, ['sign']);

      list = await keyStore.list('key', new KeyStoreOptions({ latestVersion: false }));
      if (versions) {
        expect(list[name].kids.length).toEqual(versions.kids.length + 2);
      } else {
        expect(list[name].kids.length).toEqual(2);
      }
      container = await keyStore.get(new KeyReference(name, 'key'), new KeyStoreOptions({ latestVersion: false }));
      expect(container.keys.length).toEqual(2);
    } finally {
      await (<KeyClient>keyStore.getKeyStoreClient('key')).beginDeleteKey(name);
    }
  });

  it('should sign a message', async () => {
    const name = 'KvTest-KeyStorePlugin-' + Math.random().toString(10).substr(2);
    const cache = new KeyStoreInMemory();
    const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
    const keyStore = new KeyStoreKeyVault(credential, vaultUri, cache);
    try {
      const plugin = new KeyVaultEcdsaProvider(subtle, keyStore);

      const payload = Buffer.from('test');
      console.log(payload);

      // import reference key
      let keyPair: any = await plugin.onGenerateKey(alg, false, ['sign'], { name });
      expect(keyPair.publicKey).toBeDefined();
      const signature = await plugin.onSign(alg, keyPair.publicKey, payload);
      console.log(keyPair.publicKey);

      // Set verify key
      const webCryptoAlg = clone(alg);
      webCryptoAlg.namedCurve = 'K-256';
      const jwk = await plugin.onExportKey('jwk', keyPair.publicKey);
      const cryptoKey = await subtle.importKey('jwk', jwk, webCryptoAlg, true, ['verify']);
      const result = await subtle.verify(webCryptoAlg, cryptoKey, Buffer.from(signature), payload);
      expect(result).toBeTruthy();
      expect((await cache.list())[name]).toBeUndefined();
    } finally {
      await (<KeyClient>keyStore.getKeyStoreClient('key')).beginDeleteKey(name);
    }
  });
});
describe('rsa-oaep', () => {
  const alg = { name: 'RSA-OAEP', hash: 'SHA-256', modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]) };
  it('should decrypt a message', async () => {
    const name = 'RSA-OAEP-decrypt-RSA';
    const cache = new KeyStoreInMemory();
    const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
    const keyStore = new KeyStoreKeyVault(credential, vaultUri, cache);
    try {
      const plugin = new KeyVaultRsaOaepProvider(subtle, keyStore);
      const payload = Buffer.from('hello houston');

      // generate key
      const keyPair: CryptoKeyPair = await plugin.onGenerateKey(alg, false, ['decrypt', 'encrypt']);

      // Encrypt with subtle
      const cipher = await subtle.encrypt(alg, keyPair.publicKey, payload);

      // decrypt with key vault
      const decrypt = await plugin.onDecrypt(alg, keyPair.publicKey, cipher);
      expect(Buffer.from(decrypt)).toEqual(payload);
      expect((await cache.list())[name]).toBeUndefined();
    } finally {
      await (<KeyClient>keyStore.getKeyStoreClient('key')).beginDeleteKey(name);
    }
  });
});
