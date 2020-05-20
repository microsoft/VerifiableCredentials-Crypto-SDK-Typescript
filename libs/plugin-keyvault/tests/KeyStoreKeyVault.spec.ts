/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { CryptographicKey } from '@microsoft/crypto-keys';
import { SubtleCrypto } from '@microsoft/crypto-subtle-plugin';
import KeyStoreKeyVault from '../src/keyStore/KeyStoreKeyVault';
import KeyVaultEcdsaProvider from '../src/plugin/KeyVaultEcdsaProvider';
import { KeyStoreOptions, KeyStoreInMemory } from '@microsoft/crypto-keystore';
import { KeyClient } from '@azure/keyvault-keys';
import { SecretClient } from '@azure/keyvault-secrets';
import { CryptoKey } from 'webcrypto-core';
import Credentials from './Credentials';

// Sample config
const tenantId = Credentials.tenantGuid;
const clientId = Credentials.clientId;
const clientSecret = encodeURI(Credentials.clientSecret);
const vaultUri = Credentials.vaultUri;

let originalTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
const subtle: SubtleCrypto = new SubtleCrypto();

const logging = require('adal-node').Logging;
logging.setLoggingOptions({
  log: (_level: any, _message: any, _error: any) => {
    // provide your own implementation of the log function
    // console.log(`${level}, ${message}, ${error}`);
  },
  level: logging.LOGGING_LEVEL.INFO, // provide the logging level
  loggingWithPII: true  // Determine if you want to log personal identification information. The default value is false.
});

beforeEach(async () => {
  jasmine.DEFAULT_TIMEOUT_INTERVAL = 60000;
});

afterEach(() => {
  jasmine.DEFAULT_TIMEOUT_INTERVAL = originalTimeout;
});

xdescribe('KeyStoreKeyVault', () => {
  const alg = { name: 'ECDSA', namedCurve: 'SECP256K1', hash: { name: 'SHA-256' } };
  it('should list a named generated key', async () => {
    const name = 'KvTest-KeyStoreKeyVault' + Math.random().toString(10).substr(2);
    const cache = new KeyStoreInMemory();
    const keyStore = new KeyStoreKeyVault(tenantId, clientId, clientSecret, vaultUri, cache);
    try {
      const provider = new KeyVaultEcdsaProvider(subtle, keyStore);
      await provider.onGenerateKey(alg, true, ['sign'], { name });
      let list = await keyStore.list(new KeyStoreOptions({ extractable: false, latestVersion: false }));
      expect(list[name]).toBeDefined();
      const key = await keyStore.get(name, new KeyStoreOptions({ extractable: false, latestVersion: false }));
      expect(key).toBeDefined();
      expect((await cache.list(new KeyStoreOptions({ extractable: false, latestVersion: false })))[name]).toBeUndefined();
    } finally {
      await (<KeyClient>keyStore.getKeyStoreClient(new KeyStoreOptions({ extractable: false }))).beginDeleteKey(name);
    }
  });
  it('should list a default generated key', async () => {
    const name = 'ECDSA-sign-EC';
    const cache = new KeyStoreInMemory();
    const keyStore = new KeyStoreKeyVault(tenantId, clientId, clientSecret, vaultUri, cache);
    let list = await keyStore.list(new KeyStoreOptions({ extractable: false, latestVersion: false }));
    let versionsCount = list[name] ? list[name].kids.length + 1 : 1;
    try {
      const provider = new KeyVaultEcdsaProvider(subtle, keyStore);
      await provider.onGenerateKey(alg, true, ['sign'], { name });
      let list = await keyStore.list(new KeyStoreOptions({ extractable: false, latestVersion: false }));
      expect(list[name].kids.length).toEqual(versionsCount);
    } finally {
      await (<KeyClient>keyStore.getKeyStoreClient(new KeyStoreOptions({ extractable: false }))).beginDeleteKey(name);
    }
  });
  it('should set a secret', async () => {
    const name = 'KvTest-KeyStoreKeyVault' + Math.random().toString(10).substr(2);
    const cache = new KeyStoreInMemory();
    const keyStore = new KeyStoreKeyVault(tenantId, clientId, clientSecret, vaultUri, cache);
    let throwed = false;
    try {
      await keyStore.save(name, 'abcdefg');
      const list = await keyStore.list(new KeyStoreOptions({ extractable: true, latestVersion: false }));
      expect(list[name]).toBeDefined();
      await cache.get(name);
      expect(throwed).toBeTruthy();
    } catch (err) {
      throwed = true;
      expect(err).toEqual(`${name} not found`)

    } finally {
      await (<SecretClient>keyStore.getKeyStoreClient(new KeyStoreOptions({ extractable: true }))).beginDeleteSecret(name);
    }
  });
  xit('should return a key container as a secret', async () => {
    const name = 'KvTest-KeyStoreKeyVault' + Math.random().toString(10).substr(2);
    const cache = new KeyStoreInMemory();
    const keyStore = new KeyStoreKeyVault(tenantId, clientId, clientSecret, vaultUri, cache);
    try {
      const alg = { name: 'ECDSA', namedCurve: 'secp256k1', hash: { name: 'SHA-256' } };

      const cryptoKey: any = <CryptoKey>await subtle.generateKey(alg, true, ['sign']);
      const jwk: any = await subtle.exportKey('jwk', cryptoKey.privateKey);
      jwk.kid = name;
      await keyStore.save(name, JSON.stringify(<CryptographicKey>jwk), new KeyStoreOptions({ extractable: true }));
      const container = await keyStore.get(name, new KeyStoreOptions({ extractable: true, latestVersion: false }));
      expect(container.keys.length).toEqual(1);
      expect((await cache.list(new KeyStoreOptions({ extractable: true, latestVersion: false })))[name]).toBeDefined();
    } finally {
      await (<SecretClient>keyStore.getKeyStoreClient(new KeyStoreOptions({ extractable: true }))).beginDeleteSecret(name);
    }
  });
});
