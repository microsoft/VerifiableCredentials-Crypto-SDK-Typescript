/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
 import { EllipticCurveSubtleKey } from 'verifiablecredentials-crypto-sdk-typescript-keys';
 import KeyStoreKeyVault from '../src/keyStore/KeyStoreKeyVault';
 import KeyVaultEcdsaProvider from '../src/plugin/KeyVaultEcdsaProvider';
 import KeyVaultRsaOaepProvider from '../src/plugin/KeyVaultRsaOaepProvider';
 import { KeyStoreOptions, KeyStoreInMemory } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
 import { KeyClient } from '@azure/keyvault-keys';
 import { SubtleCrypto } from 'verifiablecredentials-crypto-sdk-typescript-plugin';
import Credentials from './Credentials';
 const clone = require('clone');
 
// Sample config
const tenantId = Credentials.tenantGuid;
const clientId = Credentials.clientId;
const clientSecret = encodeURI(Credentials.clientSecret);
const vaultUri = Credentials.vaultUri;

 const subtle = new SubtleCrypto();
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
 
 xdescribe('KeyVaultPlugin', () => {
   const alg = { name: 'ECDSA', namedCurve: 'SECP256K1', hash: { name: 'SHA-256' } };
   it('should generate a key', async () => {
     const name = 'ECDSA-sign-EC';
     const cache = new KeyStoreInMemory();
     const keyStore = new KeyStoreKeyVault(tenantId, clientId, clientSecret, vaultUri, cache);
     const plugin = new KeyVaultEcdsaProvider(subtle, keyStore);
     try {
       const result = await plugin.onGenerateKey(alg, true, ['sign']);
       expect((result as EllipticCurveSubtleKey).key.crv).toEqual('SECP256K1');
       expect((result as EllipticCurveSubtleKey).algorithm).toEqual(alg);
     } finally {
       await (<KeyClient>keyStore.getKeyStoreClient(new KeyStoreOptions({extractable: false}))).beginDeleteKey(name);
     }
   });
   it('should generate a key and secret', async () => {
     const name = 'ECDSA-sign-EC';
     const cache = new KeyStoreInMemory();
     const keyStore = new KeyStoreKeyVault(tenantId, clientId, clientSecret, vaultUri, cache);
     try {
       let list = await keyStore.list(new KeyStoreOptions({extractable: false, latestVersion: false }));
       const versions = list[name];
       const plugin = new KeyVaultEcdsaProvider(subtle, keyStore);
 
       // Generate EC
       let result: any = await plugin.onGenerateKey(alg, true, ['sign']);
       const jwk = await plugin.onExportKey('jwk', new EllipticCurveSubtleKey(alg, true, ['verify'], 'public', result.key));
       list = await keyStore.list(new KeyStoreOptions({extractable: false, latestVersion: false}));
       if (versions) {
         expect(list[name].kids.length).toEqual(versions.kids.length + 1);
       } else {
         expect(list[name].kids.length).toEqual(1);
       }
 
       expect(result.algorithm).toEqual(alg);
       expect(result.extractable).toEqual(true);
       expect(result.type).toEqual('public');
       expect(result.usages).toEqual(['sign']);
       let container = await keyStore.get(name, new KeyStoreOptions({extractable: false, latestVersion: false}));
       expect(container.keys.length).toEqual(1);
       // Add new version
       (<any>jwk).kid = '#key2';
       result = await plugin.onGenerateKey(alg, true, ['sign']);
 
       list = await keyStore.list(new KeyStoreOptions({extractable: false, latestVersion: false}));
       if (versions) {
         expect(list[name].kids.length).toEqual(versions.kids.length + 2);
       } else {
         expect(list[name].kids.length).toEqual(2);
       }
       container = await keyStore.get(name, new KeyStoreOptions({extractable: false, latestVersion: false}));
       expect(container.keys.length).toEqual(2);
     } finally {
       await (<KeyClient>keyStore.getKeyStoreClient(new KeyStoreOptions({extractable: false}))).beginDeleteKey(name);
     }
   });

   it('should sign a message', async () => {
    const name = 'KvTest-KeyStorePlugin-' + Math.random().toString(10).substr(2);
    const cache = new KeyStoreInMemory();
     const keyStore = new KeyStoreKeyVault(tenantId, clientId, clientSecret, vaultUri, cache);
     try {
       const plugin = new KeyVaultEcdsaProvider(subtle, keyStore);
 
       const payload = Buffer.from('test');
       console.log(payload);
 
       // import reference key
       let result: any = await plugin.onGenerateKey(alg, true, ['sign'], { name });
       // jwk.kid = result.key.kid;
       expect(result).toBeDefined();
       let ecKey: EllipticCurveSubtleKey = await plugin.onImportKey('jwk', result.key, alg, true, ['sign']) as EllipticCurveSubtleKey;
       const signature = await plugin.onSign(alg, ecKey, payload);
       console.log(ecKey);
 
       // Set verify key
       const webCryptoAlg = clone(alg);
       webCryptoAlg.namedCurve = 'K-256';
       const jwk = await plugin.onExportKey('jwk', ecKey);
       const cryptoKey = await subtle.importKey('jwk', jwk, webCryptoAlg, true, ['verify']);
       result = await subtle.verify(webCryptoAlg, cryptoKey, Buffer.from(signature), payload);
       expect(result).toBeTruthy();
       expect((await cache.list(new KeyStoreOptions({extractable: false, latestVersion: false })))[name]).toBeUndefined();
     } finally {
       await (<KeyClient>keyStore.getKeyStoreClient(new KeyStoreOptions({extractable: false}))).beginDeleteKey(name);
     }
   });
 });
 xdescribe('rsa-oaep', () => {
   const alg = { name: 'RSA-OAEP', hash: 'SHA-256', modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]) };
   it('should decrypt a message', async () => {
     const name = 'RSA-OAEP-decrypt-RSA';
     const cache = new KeyStoreInMemory();
     const keyStore = new KeyStoreKeyVault(tenantId, clientId, clientSecret, vaultUri, cache);
     try {
       const plugin = new KeyVaultRsaOaepProvider(subtle, keyStore);
       const payload = Buffer.from('hello houston');
 
       // generate key
       const rsaKey: any = await plugin.onGenerateKey(alg, true, ['decrypt', 'encrypt']);
       const jwk = await plugin.onExportKey('jwk', rsaKey);
       let encryptKey: any = await subtle.importKey('jwk', jwk, alg, true, ['encrypt']);
 
       // Encrypt with subtle
       const cipher = await subtle.encrypt(alg, encryptKey, payload);
 
       // decrypt with key vault
       const decrypt = await plugin.onDecrypt(alg, rsaKey, cipher);
       expect(Buffer.from(decrypt)).toEqual(payload);
       expect((await cache.list(new KeyStoreOptions({extractable: false, latestVersion: false })))[name]).toBeUndefined();
     } finally {
       await (<KeyClient>keyStore.getKeyStoreClient(new KeyStoreOptions({extractable: false}))).beginDeleteKey(name);
     }
   });
 });
 