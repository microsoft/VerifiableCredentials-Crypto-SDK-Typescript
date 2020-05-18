/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
 
// tslint:disable-next-line: import-name
import { KeyTypeFactory, KeyType } from '../lib/index';

describe('KeyTypeFactory', () => {
  it(`should return the key type for 'hmac'`, () => {
    const alg = { name: 'hmac' };
    expect(KeyTypeFactory.createViaWebCrypto(alg)).toBe(KeyType.Oct);
  });

  it(`should return the key type for 'ecdsa'`, () => {
    const alg = { name: 'ecdsa' };
    expect(KeyTypeFactory.createViaWebCrypto(alg)).toBe(KeyType.EC);
  });

  it(`should return the key type for 'eddsa'`, () => {
    const alg = { name: 'eddsa' };
    expect(KeyTypeFactory.createViaWebCrypto(alg)).toBe(KeyType.OKP);
  });

  it(`should return the key type for 'ecdh'`, () => {
    const alg = { name: 'ecdh' };
    expect(KeyTypeFactory.createViaWebCrypto(alg)).toBe(KeyType.EC);
  });

  it(`should return the key type for 'rsassa-pkcs1-v1_5'`, () => {
    const alg = { name: 'rsassa-pkcs1-v1_5' };
    expect(KeyTypeFactory.createViaWebCrypto(alg)).toBe(KeyType.RSA);
  });

  it(`should return the key type for 'rsa-oaep'`, () => {
    const alg = { name: 'rsa-oaep' };
    expect(KeyTypeFactory.createViaWebCrypto(alg)).toBe(KeyType.RSA);
  });

  it(`should return the key type for 'rsa-oaep-256'`, () => {
    const alg = { name: 'rsa-oaep-256' };
    expect(KeyTypeFactory.createViaWebCrypto(alg)).toBe(KeyType.RSA);
  });

  it('should throw on unsupported algorithm', () => {
    const alg = { name: 'xxx' };
    expect(() => KeyTypeFactory.createViaWebCrypto(alg)).toThrowError(`The algorithm 'xxx' is not supported`);
  });

  it(`should return the key type for JWA 'rs256'`, () => {
    const alg = 'rs256';
    expect(KeyTypeFactory.createViaJwa(alg)).toBe(KeyType.RSA);
  });

  it(`should return the key type for JWA 'rs384'`, () => {
    const alg = 'rs384';
    expect(KeyTypeFactory.createViaJwa(alg)).toBe(KeyType.RSA);
  });

  it(`should return the key type for JWA 'rs512'`, () => {
    const alg = 'rs512';
    expect(KeyTypeFactory.createViaJwa(alg)).toBe(KeyType.RSA);
  });

  it(`should return the key type for JWA 'rsa-oaep'`, () => {
    const alg = 'rsa-oaep';
    expect(KeyTypeFactory.createViaJwa(alg)).toBe(KeyType.RSA);
  });

  it(`should return the key type for JWA 'rsa-oaep-256'`, () => {
    const alg = 'rsa-oaep-256';
    expect(KeyTypeFactory.createViaJwa(alg)).toBe(KeyType.RSA);
  });

  it(`should return the key type for JWA 'a128gcm'`, () => {
    const alg = 'a128gcm';
    expect(KeyTypeFactory.createViaJwa(alg)).toBe(KeyType.Oct);
  });
  it(`should return the key type for JWA 'a256gcm'`, () => {
    const alg = 'a256gcm';
    expect(KeyTypeFactory.createViaJwa(alg)).toBe(KeyType.Oct);
  });
  it(`should return the key type for JWA 'a192gcm'`, () => {
    const alg = 'a192gcm';
    expect(KeyTypeFactory.createViaJwa(alg)).toBe(KeyType.Oct);
  });
  
  it(`should return the key type for JWA 'es256k'`, () => {
    const alg = 'es256k';
    expect(KeyTypeFactory.createViaJwa(alg)).toBe(KeyType.EC);
  });
  
  it(`should return the key type for JWA 'secp256k1'`, () => {
    const alg = 'secp256k1';
    expect(KeyTypeFactory.createViaJwa(alg)).toBe(KeyType.EC);
  });
  
  it(`should return the key type for JWA 'ecdsa'`, () => {
    const alg = 'ecdsa';
    expect(KeyTypeFactory.createViaJwa(alg)).toBe(KeyType.EC);
  });
  
  it(`should return the key type for JWA 'eddsa'`, () => {
    const alg = 'eddsa';
    expect(KeyTypeFactory.createViaJwa(alg)).toBe(KeyType.EC);
  });
  
  it('should throw on unsupported algorithm', () => {
    const alg = 'xxx';
    expect(() => KeyTypeFactory.createViaJwa(alg)).toThrowError(`Algorithm 'xxx' is not supported`);
  });

});
