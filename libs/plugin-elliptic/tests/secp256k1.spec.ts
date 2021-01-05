/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import SubtleCryptoElliptic from '../src/SubtleCryptoElliptic';
import EllipticCurveKey from '../src/EllipticCurveKey';
import { Subtle } from 'verifiablecredentials-crypto-sdk-typescript-plugin';
import EllipticEcDsaProvider from '../src/EllipticEcDsaProvider';
  // tslint:disable:mocha-no-side-effect-code
const EC = require('elliptic').ec;

describe('secp256k1 - ECDSA', () => {
  let crypto: SubtleCryptoElliptic;
  beforeAll(() =>{
    crypto = new SubtleCryptoElliptic(new Subtle());
  });

  it('should sign/verify a message with elliptic', async () => {
    const secp256k1 = new EC('secp256k1');
    const msg = [ 0xB, 0xE, 0xE, 0xF ];
    const key = secp256k1.genKeyPair();
    const sig = key.sign(msg);

    expect(sig.r).toBeDefined();
    expect(sig.s).toBeDefined();
    const result = key.verify(msg, sig);
    expect(result).toBeTruthy();
  });

  it('should sign a message', async () => {
    const algGenerate = {
      name: 'ECDSA',
      namedCurve: 'secp256k1'
    };
    const key = await crypto.generateKey(algGenerate, true, ['sign']);

    const data = 'abcdefg';
    const alg = { name: 'ECDSA', namedCurve: 'secp256k1', hash: { name: 'SHA-256' } };
    const signature = await crypto.sign(alg, (<any> key).privateKey, Buffer.from(data));
    expect(signature.byteLength).toBeLessThanOrEqual(64);
    const publicKey: EllipticCurveKey = <EllipticCurveKey>(<any> key).publicKey;
    publicKey.usages = ['verify'];
    const result = await crypto.verify(alg, publicKey, signature, Buffer.from(data));
    expect(result).toBe(true);
  });

  it('should sign a message with DER format', async () => {
    const algGenerate = {
      name: 'ECDSA',
      namedCurve: 'secp256k1'
    };
    const key = await crypto.generateKey(algGenerate, true, ['sign']);

    const data = 'abcdefg';
    const alg = { name: 'ECDSA', namedCurve: 'secp256k1', hash: { name: 'SHA-256' }, format: 'DER' };
    const signature = await crypto.sign(alg, (<any> key).privateKey, Buffer.from(data));
    expect(signature.byteLength).toBeGreaterThanOrEqual(65);
    const publicKey: EllipticCurveKey = <EllipticCurveKey>(<any> key).publicKey;
    publicKey.usages = ['verify'];
    const result = await crypto.verify(alg, publicKey, signature, Buffer.from(data));
    expect(result).toBe(true);
  });

  it('should import and export a key', async () => {
    const algGenerate = {
      name: 'ECDSA',
      namedCurve: 'secp256k1'
    };
    const key =  <any>(await crypto.generateKey(algGenerate, true, ['sign']));
    const exported1 = await crypto.exportKey('jwk', key.privateKey);
    expect(exported1.kty).toEqual('EC');
    expect(exported1.use).toEqual('sig');
    expect(exported1.crv).toEqual('secp256k1');
    expect(exported1.d).toBeDefined();
    expect(exported1.x).toBeDefined();
    expect(exported1.y).toBeDefined();

    let imported = await crypto.importKey('jwk', exported1, algGenerate, true, ['sign']);
    let exported2 = await crypto.exportKey('jwk', imported);
    expect(exported2.kty).toEqual('EC');
    expect(exported2.use).toEqual('sig');
    expect(exported2.crv).toEqual('secp256k1');
    expect(exported2.d).toEqual(exported1.d);
    expect(exported2.x).toEqual(exported1.x);
    expect(exported2.y).toEqual(exported1.y);

    // import public key
    delete exported1.d;
    imported = await crypto.importKey('jwk', exported1, algGenerate, true, ['sign']);
    exported2 = await crypto.exportKey('jwk', imported);
    expect(exported2.kty).toEqual('EC');
    expect(exported2.use).toEqual('sig');
    expect(exported2.crv).toEqual('secp256k1');
    expect(exported2.d).toBeUndefined();
    expect(exported2.x).toEqual(exported1.x);
    expect(exported2.y).toEqual(exported1.y);
  });

  it('should throw when no jwk key is exported', async () => {
    const algGenerate = {
      name: 'ECDSA',
      namedCurve: 'secp256k1'
    };
    const key = <any>(await crypto.generateKey(algGenerate, true, ['sign']));
    let throws = false;
    await crypto.exportKey('raw', key.privateKey)
      .catch((err) => {
        throws = true;
        expect(err.message).toEqual(`Export key only supports jwk`);
      });
    expect(throws).toEqual(true);
  });

  it('should throw when no jwk key is imported', async () => {
    const algGenerate = {
      name: 'ECDSA',
      namedCurve: 'secp256k1'
    };
    let throws = false;
    await crypto.importKey('raw' , Buffer.from('aaaaaaaaaaaaa'), algGenerate, true, ['sign'])
      .catch((err) => {
        throws = true;
        expect(err.message).toEqual(`Import key only supports jwk`);
      });
    expect(throws).toEqual(true);
  });

  it('should instantiate EllipticEcDsaProvider', () => {
    const ellipticEcDsaProvider = new EllipticEcDsaProvider(crypto);
    expect(ellipticEcDsaProvider.getCurve('SECP256K1')).toBeDefined();
    expect(() => ellipticEcDsaProvider.getCurve('EdDSA')).toThrowError(`The requested curve 'EdDSA' is not supported in EllipticEcDsaProvider`);
  });

  it('should generate key in EllipticEcDsaProvider', async () => {
    const ellipticEcDsaProvider = new EllipticEcDsaProvider(crypto);
    const ec = ellipticEcDsaProvider.getCurve('SECP256K1');
    const keyPair = ec.genKeyPair();
    const genKeyPairSpy: jasmine.Spy = spyOn(ec, 'genKeyPair').and.callFake(() => {
      delete keyPair.pub;
      return keyPair;
    });
    const algGenerate = {
      name: 'ECDSA',
      namedCurve: 'secp256k1'
    };
    expect((<CryptoKeyPair>await ellipticEcDsaProvider.generateKey(algGenerate, true, ['sign'])).privateKey).toBeDefined();
    
    genKeyPairSpy.and.callFake(() => {
      keyPair.pub = keyPair.getPublic();
      return keyPair;
    });
    expect((<CryptoKeyPair>await ellipticEcDsaProvider.generateKey(algGenerate, true, ['sign'])).privateKey).toBeDefined();
  });

  it('should sign/verify in EllipticEcDsaProvider', async () => {
    const ellipticEcDsaProvider = new EllipticEcDsaProvider(crypto);
    let algGenerate: any = {
      name: 'ECDSA',
      namedCurve: 'secp256k1',
      hash: undefined
    };
    const keyPair = (<CryptoKeyPair>await ellipticEcDsaProvider.generateKey(algGenerate, true, ['sign', 'verify']));
    let signature = await ellipticEcDsaProvider.sign(algGenerate, keyPair.privateKey, new Uint8Array([1, 2, 3]));
    expect(signature).toBeDefined();
    expect(await ellipticEcDsaProvider.verify(algGenerate, keyPair.publicKey, signature, new Uint8Array([1, 2, 3])));
  });
  
});
