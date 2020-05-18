"use strict";
/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
Object.defineProperty(exports, "__esModule", { value: true });
// tslint:disable-next-line: import-name
const index_1 = require("../lib/index");
describe('KeyUseFactory', () => {
    it(`should return the key use of signature for 'hmac'`, () => {
        const alg = { name: 'hmac' };
        expect(index_1.KeyUseFactory.createViaWebCrypto(alg)).toBe(index_1.KeyUse.Signature);
    });
    it(`should return the key use of signature for 'ecdsa'`, () => {
        const alg = { name: 'ecdsa' };
        expect(index_1.KeyUseFactory.createViaWebCrypto(alg)).toBe(index_1.KeyUse.Signature);
    });
    it(`should return the key use of signature for 'eddsa'`, () => {
        const alg = { name: 'eddsa' };
        expect(index_1.KeyUseFactory.createViaWebCrypto(alg)).toBe(index_1.KeyUse.Signature);
    });
    it(`should return the key use of encryption for 'ecdh'`, () => {
        const alg = { name: 'ecdh' };
        expect(index_1.KeyUseFactory.createViaWebCrypto(alg)).toBe(index_1.KeyUse.Encryption);
    });
    it(`should return the key use of signature for 'rsassa-pkcs1-v1_5'`, () => {
        const alg = { name: 'rsassa-pkcs1-v1_5' };
        expect(index_1.KeyUseFactory.createViaWebCrypto(alg)).toBe(index_1.KeyUse.Signature);
    });
    it(`should return the key use of encryption for 'rsa-oaep'`, () => {
        const alg = { name: 'rsa-oaep' };
        expect(index_1.KeyUseFactory.createViaWebCrypto(alg)).toBe(index_1.KeyUse.Encryption);
    });
    it(`should return the key use of encryption for 'rsa-oaep-256'`, () => {
        const alg = { name: 'rsa-oaep-256' };
        expect(index_1.KeyUseFactory.createViaWebCrypto(alg)).toBe(index_1.KeyUse.Encryption);
    });
    it('should throw on unsupported algorithm', () => {
        const alg = { name: 'xxx' };
        expect(() => index_1.KeyUseFactory.createViaWebCrypto(alg)).toThrowError(`The algorithm 'xxx' is not supported`);
    });
    it(`should return the key use of signature for JWA 'rs256'`, () => {
        const alg = 'rs256';
        expect(index_1.KeyUseFactory.createViaJwa(alg)).toBe(index_1.KeyUse.Signature);
    });
    it(`should return the key use of signature for JWA 'rs384'`, () => {
        const alg = 'rs384';
        expect(index_1.KeyUseFactory.createViaJwa(alg)).toBe(index_1.KeyUse.Signature);
    });
    it(`should return the key use of signature for JWA 'rs512'`, () => {
        const alg = 'rs512';
        expect(index_1.KeyUseFactory.createViaJwa(alg)).toBe(index_1.KeyUse.Signature);
    });
    it(`should return the key use of signature for JWA 'es256k'`, () => {
        const alg = 'es256k';
        expect(index_1.KeyUseFactory.createViaJwa(alg)).toBe(index_1.KeyUse.Signature);
    });
    it(`should return the key use of signature for JWA 'secp256k1'`, () => {
        const alg = 'secp256k1';
        expect(index_1.KeyUseFactory.createViaJwa(alg)).toBe(index_1.KeyUse.Signature);
    });
    it(`should return the key use of signature for JWA 'ecdsa'`, () => {
        const alg = 'ecdsa';
        expect(index_1.KeyUseFactory.createViaJwa(alg)).toBe(index_1.KeyUse.Signature);
    });
    it(`should return the key use of signature for JWA 'rsa-oaep-256'`, () => {
        const alg = 'rsa-oaep-256';
        expect(index_1.KeyUseFactory.createViaJwa(alg)).toBe(index_1.KeyUse.Encryption);
    });
    it(`should return the key use of signature for JWA 'rsa-oaep'`, () => {
        const alg = 'rsa-oaep';
        expect(index_1.KeyUseFactory.createViaJwa(alg)).toBe(index_1.KeyUse.Encryption);
    });
    it(`should return the key use of signature for JWA 'a128gcm'`, () => {
        const alg = 'a128gcm';
        expect(index_1.KeyUseFactory.createViaJwa(alg)).toBe(index_1.KeyUse.Encryption);
    });
    it(`should return the key use of signature for JWA 'a256gcm'`, () => {
        const alg = 'a256gcm';
        expect(index_1.KeyUseFactory.createViaJwa(alg)).toBe(index_1.KeyUse.Encryption);
    });
    it(`should return the key use of signature for JWA 'a192gcm'`, () => {
        const alg = 'a192gcm';
        expect(index_1.KeyUseFactory.createViaJwa(alg)).toBe(index_1.KeyUse.Encryption);
    });
    it('should throw on unsupported algorithm', () => {
        const alg = 'xxx';
        expect(() => index_1.KeyUseFactory.createViaJwa(alg)).toThrowError(`Algorithm 'xxx' is not supported`);
    });
});
//# sourceMappingURL=KeyUseFactory.spec.js.map