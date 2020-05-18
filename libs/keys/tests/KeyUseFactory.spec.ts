/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
 
// tslint:disable-next-line: import-name
import { KeyUseFactory, KeyUse } from '../lib/index';

describe('KeyUseFactory', () => {
  it(`should return the key use of signature for 'hmac'`, () => {
    const alg = { name: 'hmac' };
    expect(KeyUseFactory.createViaWebCrypto(alg)).toBe(KeyUse.Signature);
  });

  it(`should return the key use of signature for 'ecdsa'`, () => {
    const alg = { name: 'ecdsa' };
    expect(KeyUseFactory.createViaWebCrypto(alg)).toBe(KeyUse.Signature);
  });

  it(`should return the key use of signature for 'eddsa'`, () => {
    const alg = { name: 'eddsa' };
    expect(KeyUseFactory.createViaWebCrypto(alg)).toBe(KeyUse.Signature);
  });

  it(`should return the key use of encryption for 'ecdh'`, () => {
    const alg = { name: 'ecdh' };
    expect(KeyUseFactory.createViaWebCrypto(alg)).toBe(KeyUse.Encryption);
  });

  it(`should return the key use of signature for 'rsassa-pkcs1-v1_5'`, () => {
    const alg = { name: 'rsassa-pkcs1-v1_5' };
    expect(KeyUseFactory.createViaWebCrypto(alg)).toBe(KeyUse.Signature);
  });

  it(`should return the key use of encryption for 'rsa-oaep'`, () => {
    const alg = { name: 'rsa-oaep' };
    expect(KeyUseFactory.createViaWebCrypto(alg)).toBe(KeyUse.Encryption);
  });

  it(`should return the key use of encryption for 'rsa-oaep-256'`, () => {
    const alg = { name: 'rsa-oaep-256' };
    expect(KeyUseFactory.createViaWebCrypto(alg)).toBe(KeyUse.Encryption);
  });

  it('should throw on unsupported algorithm', () => {
    const alg = { name: 'xxx' };
    expect(() => KeyUseFactory.createViaWebCrypto(alg)).toThrowError(`The algorithm 'xxx' is not supported`);
  });

  it(`should return the key use of signature for JWA 'rs256'`, () => {
    const alg = 'rs256';
    expect(KeyUseFactory.createViaJwa(alg)).toBe(KeyUse.Signature);
  });

  it(`should return the key use of signature for JWA 'rs384'`, () => {
    const alg = 'rs384';
    expect(KeyUseFactory.createViaJwa(alg)).toBe(KeyUse.Signature);
  });

  it(`should return the key use of signature for JWA 'rs512'`, () => {
    const alg = 'rs512';
    expect(KeyUseFactory.createViaJwa(alg)).toBe(KeyUse.Signature);
  });

  it(`should return the key use of signature for JWA 'es256k'`, () => {
    const alg = 'es256k';
    expect(KeyUseFactory.createViaJwa(alg)).toBe(KeyUse.Signature);
  });

  it(`should return the key use of signature for JWA 'secp256k1'`, () => {
    const alg = 'secp256k1';
    expect(KeyUseFactory.createViaJwa(alg)).toBe(KeyUse.Signature);
  });

  it(`should return the key use of signature for JWA 'ecdsa'`, () => {
    const alg = 'ecdsa';
    expect(KeyUseFactory.createViaJwa(alg)).toBe(KeyUse.Signature);
  });

  it(`should return the key use of signature for JWA 'rsa-oaep-256'`, () => {
    const alg = 'rsa-oaep-256';
    expect(KeyUseFactory.createViaJwa(alg)).toBe(KeyUse.Encryption);
  });

  it(`should return the key use of signature for JWA 'rsa-oaep'`, () => {
    const alg = 'rsa-oaep';
    expect(KeyUseFactory.createViaJwa(alg)).toBe(KeyUse.Encryption);
  });

  it(`should return the key use of signature for JWA 'a128gcm'`, () => {
    const alg = 'a128gcm';
    expect(KeyUseFactory.createViaJwa(alg)).toBe(KeyUse.Encryption);
  });

  it(`should return the key use of signature for JWA 'a256gcm'`, () => {
    const alg = 'a256gcm';
    expect(KeyUseFactory.createViaJwa(alg)).toBe(KeyUse.Encryption);
  });

  it(`should return the key use of signature for JWA 'a192gcm'`, () => {
    const alg = 'a192gcm';
    expect(KeyUseFactory.createViaJwa(alg)).toBe(KeyUse.Encryption);
  });

  it('should throw on unsupported algorithm', () => {
    const alg = 'xxx';
    expect(() => KeyUseFactory.createViaJwa(alg)).toThrowError(`Algorithm 'xxx' is not supported`);
  });
});
