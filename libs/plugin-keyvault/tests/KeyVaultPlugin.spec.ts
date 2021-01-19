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
import { Subtle, IKeyGenerationOptions } from 'verifiablecredentials-crypto-sdk-typescript-plugin';
import Credentials from './Credentials';
import { KeyVaultProvider, SubtleCryptoKeyVault } from '../src';
const clone = require('clone');

// Sample config
const tenantId = Credentials.tenantGuid;
const clientId = Credentials.clientId;
const clientSecret = encodeURI(Credentials.clientSecret);
const vaultUri = Credentials.vaultUri;
const keyVaultEnable = vaultUri.startsWith('https://');

const subtleCrypto = new Subtle();
const random = (length: number) => Math.random().toString(36).substring(2, length + 2);
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
  if (!keyVaultEnable) {
    console.log('Key vault is not enabled. Add your credentials to Credentials.ts')
    return;
  }

  const alg = { name: 'ECDSA', namedCurve: 'SECP256K1', hash: { name: 'SHA-256' } };
  it('should generate a key', async () => {
    const name = 'ECDSA-sign-EC';
    const cache = new KeyStoreInMemory();
    const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
    const keyStore = new KeyStoreKeyVault(credential, vaultUri, cache);
    const plugin = new KeyVaultEcdsaProvider(subtleCrypto, keyStore);
    try {
      const keypair: CryptoKeyPair = await plugin.onGenerateKey(alg, false, ['sign']);
      expect((<any>keypair.publicKey).algorithm.namedCurve).toEqual('K-256');
      expect(keypair.publicKey.algorithm.name).toEqual('ECDSA');
      expect((<any>keypair.publicKey.algorithm).kid.startsWith('https')).toBeTruthy();
      expect((<any>keypair.publicKey.algorithm).kid.includes(name)).toBeTruthy();

      const jwk: any = await plugin.exportKey('jwk', keypair.publicKey);
      expect(jwk.kid.startsWith('https://')).toBeTruthy();

      // negative cases
      try {
        await plugin.exportKey('raw', keypair.publicKey);
        fail('export key raw should fail');
      } catch(exception) {
        expect(exception.message).toEqual('Export key only supports jwk');
      }

    } finally {
      await (<KeyClient>keyStore.getKeyStoreClient('key')).beginDeleteKey(name);
    }
  });

  it('should generate a key with options - keyreference', async () => {
    const name = 'ECDSA-sign-EC-' + random(16);
    const cache = new KeyStoreInMemory();
    const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
    const keyStore = new KeyStoreKeyVault(credential, vaultUri, cache);
    const plugin = new KeyVaultEcdsaProvider(subtleCrypto, keyStore);
    try {
      let keyReference = new KeyReference(name, 'key');
      let curve = 'P-256K';
      let options: IKeyGenerationOptions = { keyReference, curve };
      const result: CryptoKeyPair = await plugin.onGenerateKey(alg, false, ['sign'], options);
      expect((<any>result.publicKey).algorithm.namedCurve).toEqual('K-256');
      expect(result.publicKey.algorithm.name).toEqual('ECDSA');
      expect((<any>result.publicKey.algorithm).kid.startsWith('https')).toBeTruthy();
      expect((<any>result.publicKey.algorithm).kid.includes(name)).toBeTruthy();
    } finally {
      await (<KeyClient>keyStore.getKeyStoreClient('key')).beginDeleteKey(name);
    }
  });

  it('should generate a key with options - remoteKeyreference', async () => {
    const name = 'ECDSA-sign-EC-' + random(16);
    const remoteName = 'ECDSA-sign-EC-' + random(16) + '-remote';
    const cache = new KeyStoreInMemory();
    const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
    const keyStore = new KeyStoreKeyVault(credential, vaultUri, cache);
    const plugin = new KeyVaultEcdsaProvider(subtleCrypto, keyStore);
    try {

      let keyReference = new KeyReference(name, 'key', remoteName);
      let curve = 'P-256K';
      let options: IKeyGenerationOptions = { keyReference, curve };
      const result: CryptoKeyPair = await plugin.onGenerateKey(alg, false, ['sign'], options);
      expect((<any>result.publicKey).algorithm.namedCurve).toEqual('K-256');
      expect(result.publicKey.algorithm.name).toEqual('ECDSA');
      expect((<any>result.publicKey.algorithm).kid.startsWith('https')).toBeTruthy();
      expect((<any>result.publicKey.algorithm).kid.includes(remoteName)).toBeTruthy();
    } finally {
      await (<KeyClient>keyStore.getKeyStoreClient('key')).beginDeleteKey(remoteName);
    }
  });

  it('should sign with key vault EC key', async () => {
    const name = 'ECDSA-sign-EC-' + random(16);
    const remoteName = 'ECDSA-sign-EC-' + random(16) + '-remote';
    const cache = new KeyStoreInMemory();
    const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
    const keyStore = new KeyStoreKeyVault(credential, vaultUri, cache);
    const subtleKv = new SubtleCryptoKeyVault(new Subtle(), keyStore);
    try {

      const keyReference = new KeyReference(name, 'key', remoteName);
      const curve = 'P-256K';
      const alg = { name: 'ECDSA', namedCurve: 'secp256k1', hash: { name: 'SHA-256' } };
      const keypair = await subtleKv.generateKey(alg, false, ['sign', 'verify'], { keyReference, curve });
      const payload = Buffer.from('hello Houston');
      const signature = await subtleKv.sign(alg, keypair.publicKey, payload);
      expect(signature.byteLength).toEqual(64);

      const jwk = await subtleKv.exportKey('jwk', keypair.publicKey);
      expect(jwk.kty).toEqual('EC');

      // negative cases
      let publicKey = clone(keypair.publicKey);
      delete (<any>publicKey.algorithm).kid;
      try {
        await subtleKv.sign(alg, publicKey, payload);
        fail('sign should throw');
      } catch(exception) {
        expect(exception.message).toEqual('Missing kid in algortihm');
      }

      let getCryptoClientSpy: jasmine.Spy = spyOn(keyStore, 'getCryptoClient').and.callFake(() => {
        return {
          sign: () => Promise.reject(new Error('spy signing error'))
        };
      });
      try {
        await subtleKv.sign(alg, keypair.publicKey, payload);
        fail('sign should throw');
      } catch(exception) {
        expect(exception.message).toEqual('spy signing error');
      }

    } finally {
      await (<KeyClient>keyStore.getKeyStoreClient('key')).beginDeleteKey(remoteName);
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
      const plugin = new KeyVaultEcdsaProvider(subtleCrypto, keyStore);

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
      const plugin = new KeyVaultEcdsaProvider(subtleCrypto, keyStore);

      const payload = Buffer.from('test');
      console.log(payload);

      // import reference key
      let keyPair: any = await plugin.onGenerateKey(alg, false, ['sign'], { keyReference: new KeyReference(name) });
      expect(keyPair.publicKey).toBeDefined();
      const signature = await plugin.onSign(alg, keyPair.publicKey, payload);
      console.log(keyPair.publicKey);

      // Set verify key
      const webCryptoAlg = clone(alg);
      webCryptoAlg.namedCurve = 'K-256';
      const jwk = await (await cache.get(new KeyReference(name, 'key'), keyPair.publicKey)).getKey<JsonWebKey>();
      const cryptoKey = await subtleCrypto.importKey('jwk', jwk, webCryptoAlg, true, ['verify']);
      const result = await subtleCrypto.verify(webCryptoAlg, cryptoKey, Buffer.from(signature), payload);
      expect(result).toBeTruthy();
      expect((await cache.list())[name]).toBeDefined();
    } finally {
      await (<KeyClient>keyStore.getKeyStoreClient('key')).beginDeleteKey(name);
    }
  });


  it('should sign a message with imported key', async () => {

    const name = 'KvTest-KeyStorePlugin-' + Math.random().toString(10).substr(2);
    const cache = new KeyStoreInMemory();
    const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
    const keyStore = new KeyStoreKeyVault(credential, vaultUri, cache);
    try {
      const plugin = new KeyVaultEcdsaProvider(subtleCrypto, keyStore);

      const payload = Buffer.from('test');
      console.log(payload);

      // import reference key
      const keyReference = new KeyReference(name, 'key');
      let cryptoKey: any = <CryptoKey>await subtleCrypto.generateKey(alg, true, ['sign'], { keyReference });
      let jwk: any = await subtleCrypto.exportKey('jwk', cryptoKey.privateKey);
      jwk.kid = name;

      await keyStore.save(keyReference, jwk, new KeyStoreOptions());
      console.log(`Key saved in key store`);

      const cachedPublic = await (await cache.get(keyReference)).getKey<JsonWebKey>();

      cryptoKey = await plugin.importKey('jwk', cachedPublic, alg, false, ['sign']);
      const signature = await plugin.sign(alg, cryptoKey, payload);

      // Set verify key
      const webCryptoAlg = clone(alg);
      webCryptoAlg.namedCurve = 'K-256';
      jwk = (await cache.get(new KeyReference(name, 'key'), new KeyStoreOptions({ publicKeyOnly: true }))).getKey<JsonWebKey>();
      cryptoKey = await subtleCrypto.importKey('jwk', jwk, webCryptoAlg, true, ['verify']);
      const result = await subtleCrypto.verify(webCryptoAlg, cryptoKey, signature, payload);
      expect(result).toBeTruthy();
      expect((await cache.list())[name]).toBeDefined();

      // negative cases
      try {
        await plugin.importKey('raw', new Uint8Array([1,2,3,4]), webCryptoAlg, true, ['sign']);
        fail('import raw should fail');
      } catch (exception) {
        expect(exception.message).toEqual('Import key only supports jwk');
      }
      let clonedJwk = clone(jwk);
      clonedJwk.kty = 'RSA'
      try {
        await plugin.importKey('jwk', clonedJwk, webCryptoAlg, true, ['sign']);
        fail('import RSA should fail');
      } catch (exception) {
        expect(exception.message).toEqual('Import key only supports kty EC');
      }
      clonedJwk = clone(jwk);
      clonedJwk.crv = 'ed25519';
      try {
        await plugin.importKey('jwk', clonedJwk, webCryptoAlg, true, ['sign']);
        fail('import crv should fail');
      } catch (exception) {
        expect(exception.message).toEqual('Import key only supports crv P-256K');
      }
      clonedJwk = clone(jwk);
      delete clonedJwk.kid;
      try {
        await plugin.importKey('jwk', clonedJwk, webCryptoAlg, true, ['sign']);
        fail('import crv should fail');
      } catch (exception) {
        expect(exception.message).toEqual('Imported key must have a kid in the format https://<vault>/keys/<name>/<version>');
      }
      clonedJwk = clone(jwk);
      clonedJwk.kid = 'vaultUri';
      try {
        await plugin.importKey('jwk', clonedJwk, webCryptoAlg, true, ['sign']);
        fail('import crv should fail');
      } catch (exception) {
        expect(exception.message).toEqual('Imported key must have a kid in the format https://<vault>/keys/<name>/<version>');
      }
      clonedJwk = clone(jwk);
      clonedJwk.kid = 'https://vault.com';
      try {
        await plugin.importKey('jwk', clonedJwk, webCryptoAlg, true, ['sign']);
        fail('import crv should fail');
      } catch (exception) {
        expect(exception.message).toEqual('Imported key must be of type keys or secrets');
      }
    } finally {
      await (<KeyClient>keyStore.getKeyStoreClient('key')).beginDeleteKey(name);
    }
  });

  it('should create a key pair', async () => {
    const key = {};
    const cache = new KeyStoreInMemory();
    const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
    const keyStore = new KeyStoreKeyVault(credential, vaultUri, cache);
    const pair = await KeyVaultProvider.toCryptoKeyPair(alg, true, ['verify'], key);
    expect(pair.publicKey.algorithm).toEqual(alg);
    expect(pair.publicKey.extractable).toBeTruthy;
    expect(pair.publicKey.type).toEqual('public');
    expect(pair.publicKey.usages).toEqual(['verify']);
  });

  it('should check performance', async () => {

    const name = 'KvTest-KeyStorePlugin-performanceTest';
    const cache = new KeyStoreInMemory();
    const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
    const keyStore = new KeyStoreKeyVault(credential, vaultUri, cache);
    try {
      const plugin = new KeyVaultEcdsaProvider(subtleCrypto, keyStore);

      // Generate EC
      let keyReference = new KeyReference(name, 'key');
      let curve = 'P-256K';
      let options: IKeyGenerationOptions = { keyReference, curve };
      for (let inx = 0; inx < 1; inx++) {        
        let result: any = await plugin.onGenerateKey(alg, false, ['sign'], options);
        let timer = Math.trunc(Date.now());
        console.log(`Iteration --> ${inx}. Start get timer: ${timer}`);
        let keyContainer = await keyStore.get(keyReference);
        console.log(`Timer after keyStore get - no version: ${Math.trunc(Date.now()) - timer} milliseconds`);
        timer = Math.trunc(Date.now());
        console.log(`Start sign timer: ${timer}`);
        result = await plugin.onSign(alg, result.publicKey, Buffer.from('abcdef'));
        console.log(`Timer after sign: ${Math.trunc(Date.now()) - timer} milliseconds`);
      }

    } finally {
      await (<KeyClient>keyStore.getKeyStoreClient('key')).beginDeleteKey(name);
    }
  });
});

describe('rsa-oaep', () => {
  if (!keyVaultEnable) {
    console.log('Key vault is enabled. Add your credentials to Credentials.ts')
    return;
  }

  const alg = { name: 'RSA-OAEP', hash: 'SHA-256', modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]) };
  it('should decrypt a message', async () => {
    const name = 'RSA-OAEP-decrypt-RSA';
    const cache = new KeyStoreInMemory();
    const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
    const keyStore = new KeyStoreKeyVault(credential, vaultUri, cache);
    try {
      const plugin = new KeyVaultRsaOaepProvider(subtleCrypto, keyStore);
      const payload = Buffer.from('hello houston');

      // generate key
      const keyPair: CryptoKeyPair = await plugin.onGenerateKey(alg, false, ['decrypt', 'encrypt']);

      // Encrypt with subtle
      const cipher = await subtleCrypto.encrypt(alg, keyPair.publicKey, payload);

      // decrypt with key vault
      const decrypt = await plugin.onDecrypt(alg, keyPair.publicKey, cipher);
      expect(Buffer.from(decrypt)).toEqual(payload);
      expect((await cache.list())[name]).toBeDefined();

      // negative cases
      let clonedPk = clone(keyPair.publicKey);
      delete clonedPk.algorithm.kid;

      try {
        await plugin.decrypt(alg, clonedPk, cipher);
        fail('decrypt RSA should fail');
      } catch (exception) {
        expect(exception.message).toEqual('Missing kid in algortihm');
      }

    } finally {
      await (<KeyClient>keyStore.getKeyStoreClient('key')).beginDeleteKey(name);
    }
  });
});
