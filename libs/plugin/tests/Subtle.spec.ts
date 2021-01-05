/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { Subtle } from '../lib';

describe('Subtle', () => {
    it('should create instance', () => {
        let subtle: any = new Subtle();
        expect(subtle.getSubtleCrypto().constructor.name).toEqual('Subtle');
    });
    it('should test algorithmTransform', () => {
        let subtle = new Subtle();
        let alg: any = { test: 'name' };
        expect(subtle.algorithmTransform(alg)).toEqual(alg);
        alg = { namedCurve: 'P-256K' };
        expect(subtle.algorithmTransform(alg)).toEqual({ namedCurve: 'K-256' });
        alg = { namedCurve: 'SECP256K1' };
        expect(subtle.algorithmTransform(alg)).toEqual({ namedCurve: 'K-256' });
        alg = { crv: 'P-256K' };
        expect(subtle.algorithmTransform(alg)).toEqual({ crv: 'K-256' });
        alg = { crv: 'SECP256K1' };
        expect(subtle.algorithmTransform(alg)).toEqual({ crv: 'K-256' });
    });
    it('should test keyImportTransform', () => {
        let subtle: any = new Subtle();
        let jwk: any = { test: 'name' };
        expect(subtle.keyImportTransform(jwk)).toEqual(jwk);
        jwk = { foo: 'fighters' };
        expect(subtle.keyImportTransform(jwk)).toEqual(jwk);
        jwk = { crv: 'P-256K' };
        expect(subtle.keyImportTransform(jwk)).toEqual({ crv: 'K-256' });
        jwk = { crv: 'SECP256K1' };
        expect(subtle.keyImportTransform(jwk)).toEqual({ crv: 'K-256' });
        jwk = { crv: 'XXX' };
        expect(subtle.keyImportTransform(jwk)).toEqual({ crv: 'XXX' });

    });
    it('should test keyExportTransform', () => {
        let subtle: any = new Subtle();
        let jwk: any = { test: 'name' };
        expect(subtle.keyExportTransform(jwk)).toEqual(jwk);
        jwk = { foo: 'fighters' };
        expect(subtle.keyExportTransform(jwk)).toEqual(jwk);
        jwk = { crv: 'P-256K' };
        expect(subtle.keyExportTransform(jwk)).toEqual({ crv: 'SECP256K1' });
        jwk = { crv: 'K-256' };
        expect(subtle.keyExportTransform(jwk)).toEqual({ crv: 'SECP256K1' });
        jwk = { crv: 'SECP256K1' };
        expect(subtle.keyExportTransform(jwk)).toEqual({ crv: 'SECP256K1' });
    });
    it('should test digest', async() => {
        let subtle: any = new Subtle();
        let alg: any = { name: 'SHA-256' };
        expect(await subtle.digest(alg, new Uint8Array([1,2,3,4]))).toBeDefined();
    });
    it('should test generate/export', async() => {
        let subtle = new Subtle();
        let alg: any = { name: "HMAC", hash: {name: "SHA-256"} };
        const key = <CryptoKey>await subtle.generateKey(alg, true, ['sign']);
        expect(key).toBeDefined();
        let jwk: any = await subtle.exportKey('raw', key);
        expect(new Uint8Array(jwk)[0]).toBeDefined();
        let cryptoKey = await subtle.importKey('raw', jwk, alg, true, ['sign']);
        expect(cryptoKey).toBeDefined();
        jwk = await subtle.exportKey('jwk', key);
        expect(jwk.k).toBeDefined();
        jwk = await subtle.importKey('jwk', jwk, alg, true, ['sign']);
        expect(jwk.type).toEqual('secret');
    });
});