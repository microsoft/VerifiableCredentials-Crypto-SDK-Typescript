/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { SubtleCryptoElliptic, EllipticCurveKey}  from '../src/index';
import base64url from 'base64url';
import { SubtleCrypto } from 'verifiablecredentials-crypto-sdk-typescript-plugin';


const algGenerate = {
  name: 'EDDSA',
  namedCurve: 'ed25519'
};

describe('ed25519 - EDDSA', () => {
  let crypto: SubtleCryptoElliptic;
  // tslint:disable:mocha-no-side-effect-code
  const EC = require('elliptic');
  var eddsa = EC.eddsa;
  const ed25519 = new eddsa('ed25519');
  const messageReference= 'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc';
  const message = Buffer.from(messageReference);
  const secretReference = [0x9d ,0x61 ,0xb1 ,0x9d ,0xef ,0xfd ,0x5a ,0x60 ,0xba ,0x84 ,0x4a ,0xf4 ,0x92 ,0xec ,0x2c ,0xc4 ,0x44 ,0x49 ,0xc5 ,0x69 ,0x7b ,0x32 ,0x69 ,0x19 ,0x70 ,0x3b ,0xac ,0x03 ,0x1c ,0xae ,0x7f ,0x60];
  const publicReference = [0xd7 ,0x5a ,0x98 ,0x01 ,0x82 ,0xb1 ,0x0a ,0xb7 ,0xd5 ,0x4b ,0xfe ,0xd3 ,0xc9 ,0x64 ,0x07 ,0x3a ,0x0e ,0xe1 ,0x72 ,0xf3 ,0xda ,0xa6 ,0x23 ,0x25 ,0xaf ,0x02 ,0x1a ,0x68 ,0xf7 ,0x07 ,0x51 ,0x1a];
  const signatureReference= '860c98d2297f3060a33f42739672d61b53cf3adefed3d3c672f320dc021b411e9d59b8628dc351e248b88b29468e0e41855b0fb7d83bb15be902bfccb8cd0a02'.toUpperCase();

  beforeAll(() =>{
    crypto = new SubtleCryptoElliptic(new SubtleCrypto()).getSubtleCrypto();
  });

  it('should sign/verify a reference message with elliptic', async () => {
    const inverseSecret = [];
    for (let inx=secretReference.length - 1; inx > 0 ; inx --) {
      inverseSecret.push(secretReference[inx]);
    }
                      
    const publicPair = ed25519.keyFromPublic(publicReference);
    const result = publicPair.verify(message, signatureReference);
    expect(result).toBeTruthy();

    const keyPair = ed25519.keyFromSecret(secretReference);
    let pub = keyPair.getPublic();
    expect(pub).toBeDefined();
    let signature = keyPair.sign(message).toHex();
    expect(signature.slice(0, 64)).toEqual(signatureReference.slice(0, 64));
    expect(signature.slice(64)).toEqual(signatureReference.slice(64));
  });

  it('should sign/verify a message with elliptic', async () => {
    const msg = [ 0xB, 0xE, 0xE, 0xF ];
    const secret = Buffer.alloc(32, 0);
    const key = ed25519.keyFromSecret(secret);
    let d = base64url.encode(secret);
    let pub = key.getPublic();
    let x = base64url.encode(pub);
    expect(d).toBeDefined();
    expect(x).toBeDefined();
    let sig = key.sign(msg).toHex();
    var R = '8F1B9A7FDB22BCD2C15D4695B1CE2B063CBFAEC9B00BE360427BAC9533943F6C';
    var S = '5F0B380FD7F2E43B70AB2FA29F6C6E3FFC1012710E174786814012324BF19B0C';
    expect(sig.slice(0, 64)).toEqual(R);
    expect(sig.slice(64)).toEqual(S);
    let result = key.verify(msg, sig);
    expect(result).toBeTruthy();
    const importedPublic = ed25519.keyFromPublic(pub);
    expect(importedPublic.verify(msg, sig)).toBeTruthy();

    const importKey = ed25519.keyFromSecret(base64url.toBuffer(d));
    const newSig = importKey.sign(msg).toHex();
    expect(newSig).toEqual(sig);
  });

  it('should generate a key', async () => {
    const key =  <CryptoKeyPair>(await crypto.generateKey(algGenerate, true, ['sign']));
    expect(key.publicKey.algorithm).toEqual(algGenerate);
    expect(key.publicKey.usages).toEqual(['sign']);
    expect(key.publicKey.type).toEqual('public');
    expect(key.privateKey.algorithm).toEqual(algGenerate);
    expect(key.privateKey.usages).toEqual(['sign']);
    expect(key.privateKey.type).toEqual('private');
  });

  it('should import and export a key', async () => {
    const key =  <any>(await crypto.generateKey(algGenerate, true, ['sign']));
    const exported1 = await crypto.exportKey('jwk', key.privateKey);
    expect(exported1.kty).toEqual('OKP');
    expect(exported1.use).toEqual('sig');
    expect(exported1.crv).toEqual('ed25519');
    expect(exported1.d).toBeDefined();
    expect(exported1.x).toBeDefined();
    expect(exported1.y).toBeUndefined();
    
    let imported: any  = await crypto.importKey('jwk', exported1, algGenerate, true, ['sign']);
    let exported2 = await crypto.exportKey('jwk', imported);
    expect(exported1.kty).toEqual('OKP');
    expect(exported2.use).toEqual('sig');
    expect(exported2.crv).toEqual('ed25519');
    expect(exported2.d).toEqual(exported1.d);
    expect(exported2.x).toEqual(exported1.x);
    expect(exported2.y).toEqual(exported1.y);

    // import public key
    delete exported1.d;
    imported = await crypto.importKey('jwk', exported1, algGenerate, true, ['sign']);
    exported2 = await crypto.exportKey('jwk', imported);
    expect(exported1.kty).toEqual('OKP');
    expect(exported2.use).toEqual('sig');
    expect(exported2.crv).toEqual('ed25519');
    expect(exported2.d).toBeUndefined();
    expect(exported2.x).toEqual(exported1.x);
    expect(exported2.y).toEqual(exported1.y);
  });

  it('should verify evernyms reference message', async () => {
    const jwk = {
      'crv':'Ed25519',
      'kty':"OKP",
      'd': 'QsI1MjsfmA4nL3zks3h0wfSTq6bqfM5nSacxWiUO_pg',
      'x':'5CW946ZRobK15OJjrL3O3ivW7_lsuekMpCrk8YH21pw'
    }
    const alg = { name: 'EDDSA', namedCurve: 'ed25519', hash: { name: 'SHA-256' } };
    let key: any = await crypto.importKey('jwk', jwk, alg, true, ['sign', 'verify']);

    const referenceMessage = Buffer.from('The rain in Spain stays mainly in the plain!');
    const signature = await crypto.sign(alg, key, referenceMessage);
    expect(base64url.encode(Buffer.from(signature))).toEqual('_9N24HjHV96A0vCJlkunCctJ44B-KN_BcBy3M2eX8LnFjFUPzb9w4Ek744HBj7H0arEK3uOgEzBCNzp-N8oJDA');

    delete jwk.d;
    key = await crypto.importKey('jwk', jwk, alg, true, ['sign', 'verify']);
    const result = await crypto.verify(alg, key, signature, referenceMessage);
    expect(result).toBeTruthy();
  });


  it('should sign a reference message', async () => {
    const jwk = {
      'crv':'Ed25519',
      'kty':"OKP",
      'd': 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A',
      'x':'11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo'
    }
    const alg = { name: 'EDDSA', namedCurve: 'ed25519', hash: { name: 'SHA-256' } };
    const key: any = await crypto.importKey('jwk', jwk, alg, true, ['sign', 'verify']);

    const signature = await crypto.sign(alg, key, message);
    const r = Buffer.from(signature.slice(0, 32));
    const s = Buffer.from(signature.slice(32));
    expect(r).toEqual(Buffer.from(signatureReference.slice(0, 64), 'hex'));
    expect(s).toEqual(Buffer.from(signatureReference.slice(64), 'hex'));
    const result = await crypto.verify(alg, key, signature, message);
    expect(result).toBe(true);
  });

  it('should sign a message', async () => {
    const key = await crypto.generateKey(algGenerate, true, ['sign']);

    const data = 'abcdefg';
    const alg = { name: 'EDDSA', namedCurve: 'ed25519', hash: { name: 'SHA-256' } };
    const signature = await crypto.sign(alg, (<any> key).privateKey, Buffer.from(data));
    expect(signature.byteLength).toBeLessThanOrEqual(64);
    const publicKey: EllipticCurveKey = <EllipticCurveKey>(<CryptoKeyPair> key).publicKey;
    publicKey.usages = ['verify'];
    const result = await crypto.verify(alg, publicKey, signature, Buffer.from(data));
    expect(result).toBe(true);
  });

  it('should sign a message with DER format', async () => {
    const key = await crypto.generateKey(algGenerate, true, ['sign']);

    const data = 'abcdefg';
    const alg = { name: 'EDDSA', namedCurve: 'ed25519', hash: { name: 'SHA-256' }, format: 'DER' };
    const signature = await crypto.sign(alg, (<any> key).privateKey, Buffer.from(data));
    expect(signature.byteLength).toBeGreaterThanOrEqual(70);
    const publicKey: EllipticCurveKey = <EllipticCurveKey>(<any> key).publicKey;
    publicKey.usages = ['verify'];
    const result = await crypto.verify(alg, publicKey, signature, Buffer.from(data));
    expect(result).toBe(true);
  });

  it('should throw when no jwk key is exported', async () => {
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
    let throws = false;
    await crypto.importKey('raw' , Buffer.from('aaaaaaaaaaaaa'), algGenerate, true, ['sign'])
      .catch((err) => {
        throws = true;
        expect(err.message).toEqual(`Import key only supports jwk`);
      });
    expect(throws).toEqual(true);
  });
});
