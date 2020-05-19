/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { CryptoFactory, CryptoFactoryScope, CryptoHelpers, SubtleCryptoExtension } from '../lib';
import { KeyStoreInMemory, KeyReferenceOptions } from '@microsoft/crypto-keystore';
import { SubtleCryptoNode, CryptoFactoryNode } from '../lib';
import EcPrivateKey from '@microsoft/crypto-keys/dist/lib/ec/EcPrivateKey';
import { KeyContainer, PublicKey } from '@microsoft/crypto-keys';


describe('SubtleCryptoExtension', () => {
  const keyStore = new KeyStoreInMemory();
  const cryptoFactory = new CryptoFactoryNode(keyStore, new SubtleCryptoNode().getSubtleCrypto());
  const generator = new SubtleCryptoExtension(cryptoFactory);
  
  it('should generate an ECDSA key', async () => {
    const alg = CryptoHelpers.jwaToWebCrypto('Es256K');
    const key: any = <CryptoKey> await generator.generateKey(
      alg,
      true, 
      ['sign', 'verify']
    );
    const jwk = await generator.exportJwkKey(alg, key.privateKey, CryptoFactoryScope.Private);
    expect(jwk.d).toBeDefined();
    expect(jwk.x).toBeDefined();
    expect(jwk.y).toBeDefined();
    expect(jwk.kty).toEqual('EC');
  });
 
  it('should generate an RSA key', async () => {
    const alg = CryptoHelpers.jwaToWebCrypto('RSA-OAEP');
    const key: any = <CryptoKey> await generator.generateKey(
      alg,
      true, 
      ['encrypt', 'decrypt']
    );
    const jwk = await generator.exportJwkKey(alg, key.privateKey, CryptoFactoryScope.Private);
    expect(jwk.d).toBeDefined();
    expect(jwk.n).toBeDefined();
    expect(jwk.e).toBeDefined();
    expect(jwk.kty).toEqual('RSA');
  });
  
  it('should generate an oct key', async () => {
    const alg = CryptoHelpers.jwaToWebCrypto('A128GCM');
    const key: any = <CryptoKey> await generator.generateKey(
      alg,
      true, 
      ['encrypt', 'decrypt']
    );
    const jwk = await generator.exportJwkKey(alg, key, CryptoFactoryScope.Private);
    expect(jwk.k).toBeDefined();
    expect(jwk.kty).toEqual('oct');
  });
  it('should sign a message', async() => {
    const keyStore = new KeyStoreInMemory();
    const factory = new CryptoFactoryNode(keyStore, SubtleCryptoNode.getSubtleCrypto());
    const subtle = new SubtleCryptoExtension(factory);
    const alg = { name: 'ECDSA', namedCurve: 'secp256k1', hash: { name: 'SHA-256' }, format: 'DER' };

    const jwk = new EcPrivateKey({"kid":"#signing","kty":"EC","use":"sig","alg":"ES256K","crv":"secp256k1","x":"7RlJnsuYQuSNdpRAFwejCXZqsAccW_QKWw4dPmABBVA","y":"nf0vn9ib6ObyLm4WaDWUe8g3gkEwo2jVbthS7R4MsaU","d":"2PtA4bb6fXprFLfjIJsi5Cer8YAdEDVDomYNYK9ppkU"});
    await keyStore.save('key', jwk);
    const payload = Buffer.from('test');
    let signature = await subtle.signByKeyStore(alg, 'key', payload);
    expect(signature.byteLength).toBeGreaterThan(65);
    const publicKey = (await keyStore.get('key')).getKey<PublicKey>();
    let result = await subtle.verifyByJwk(alg, publicKey, signature, payload);
    expect(result).toBeTruthy();

    // without DER
    delete alg.format;
    signature = await subtle.signByKeyStore(alg, 'key', payload);
    expect(signature.byteLength).toBeLessThanOrEqual(64);    
    result = await subtle.verifyByJwk(alg, publicKey, signature, payload);
    expect(result).toBeTruthy();
  });
  it('should sign a message with key reference options', async() => {
    const keyStore = new KeyStoreInMemory();
    const factory = new CryptoFactoryNode(keyStore, SubtleCryptoNode.getSubtleCrypto());
    const subtle = new SubtleCryptoExtension(factory);
    const alg = { name: 'ECDSA', namedCurve: 'secp256k1', hash: { name: 'SHA-256' }, format: 'DER' };

    const jwk = new EcPrivateKey({"kid":"#signing","kty":"EC","use":"sig","alg":"ES256K","crv":"secp256k1","x":"7RlJnsuYQuSNdpRAFwejCXZqsAccW_QKWw4dPmABBVA","y":"nf0vn9ib6ObyLm4WaDWUe8g3gkEwo2jVbthS7R4MsaU","d":"2PtA4bb6fXprFLfjIJsi5Cer8YAdEDVDomYNYK9ppkU"});
    await keyStore.save('key', jwk);
    const payload = Buffer.from('test');
    let signature = await subtle.signByKeyStore(alg, new KeyReferenceOptions({ keyReference: 'key', extractable: true }), payload);
    expect(signature.byteLength).toBeGreaterThan(65);
    const publicKey = (await keyStore.get('key')).getKey<PublicKey>();
    let result = await subtle.verifyByJwk(alg, publicKey, signature, payload);
    expect(result).toBeTruthy();
  });
});
