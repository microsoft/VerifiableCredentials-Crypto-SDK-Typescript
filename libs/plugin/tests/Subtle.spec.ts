/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { Subtle, CryptoFactory, CryptoFactoryScope, CryptoHelpers, SubtleCryptoExtension } from '../lib';
import { KeyStoreInMemory, KeyReference } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import EcPrivateKey from 'verifiablecredentials-crypto-sdk-typescript-keys/dist/lib/ec/EcPrivateKey';
import { PublicKey, JsonWebKey } from 'verifiablecredentials-crypto-sdk-typescript-keys';
import base64url from 'base64url';

fdescribe('Subtle', () => {
    it('should create instance', () => {
        let subtle: any = new Subtle();
        expect(subtle.getSubtleCrypto().constructor.name).toEqual('Subtle');
    });
    it('should test algorithmTransform', () => {
        let subtle = new Subtle();
        let alg: any = {test: 'name'};
        expect(subtle.algorithmTransform(alg)).toEqual(alg);
        alg = {namedCurve: 'P-256K'};
        expect(subtle.algorithmTransform(alg)).toEqual({namedCurve: 'K-256'});
        alg = {namedCurve: 'SECP256K1'};
        expect(subtle.algorithmTransform(alg)).toEqual({namedCurve: 'K-256'});
        alg = {crv: 'P-256K'};
        expect(subtle.algorithmTransform(alg)).toEqual({crv: 'K-256'});
        alg = {crv: 'SECP256K1'};
        expect(subtle.algorithmTransform(alg)).toEqual({crv: 'K-256'});
    });
    it('should test keyImportTransform', () => {
        let subtle: any = new Subtle();
        let jwk: any = {test: 'name'};
        expect(subtle.keyImportTransform(jwk)).toEqual(jwk);
        jwk = {foo: 'fighters'};
        expect(subtle.keyImportTransform(jwk)).toEqual(jwk);
        jwk = {crv: 'P-256K'};
        expect(subtle.keyImportTransform(jwk)).toEqual({crv: 'K-256'});
        jwk = {crv: 'SECP256K1'};
        expect(subtle.keyImportTransform(jwk)).toEqual({crv: 'K-256'});

    });
    it('should test keyExportTransform', () => {
        let subtle: any = new Subtle();
        let jwk: any = {test: 'name'};
        expect(subtle.keyExportTransform(jwk)).toEqual(jwk);
        jwk = {foo: 'fighters'};
        expect(subtle.keyExportTransform(jwk)).toEqual(jwk);
        jwk = {crv: 'P-256K'};
        expect(subtle.keyExportTransform(jwk)).toEqual({crv: 'SECP256K1'});
        jwk = {crv: 'K-256'};
        expect(subtle.keyExportTransform(jwk)).toEqual({crv: 'SECP256K1'});
        jwk = {crv: 'SECP256K1'};
        expect(subtle.keyExportTransform(jwk)).toEqual({crv: 'SECP256K1'});
 });
});