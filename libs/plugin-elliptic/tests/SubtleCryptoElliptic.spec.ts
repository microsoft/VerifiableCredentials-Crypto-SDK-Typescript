/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import SubtleCryptoElliptic from '../src/SubtleCryptoElliptic';
import { Subtle } from 'verifiablecredentials-crypto-sdk-typescript-plugin';

describe('SubtleCryptoElliptic', () => {
    it('should create a SubtleCryptoElliptic', () => {
        const subtleCryptoElliptic = new SubtleCryptoElliptic(new Subtle());
        expect(subtleCryptoElliptic.getSubtleCrypto().constructor.name).toEqual('SubtleCryptoElliptic');
    });

    it('should test algorithmTransform', () => {
        let subtle = new SubtleCryptoElliptic(new Subtle());
        let alg: any = {test: 'name'};
        expect(subtle.algorithmTransform(alg)).toEqual(alg);
        alg = {foo: 'fighters'};
        expect(subtle.algorithmTransform(alg)).toEqual(alg);
    });
    it('should test keyImportTransform', () => {
        let subtle: any = new SubtleCryptoElliptic(new Subtle());
        let jwk: any = {test: 'name'};
        expect(subtle.keyImportTransform(jwk)).toEqual(jwk);
        jwk = {foo: 'fighters'};
        expect(subtle.keyImportTransform(jwk)).toEqual(jwk);
    });
    it('should test keyExportTransform', () => {
        let subtle: any = new SubtleCryptoElliptic(new Subtle());
        let jwk: any = {test: 'name'};
        expect(subtle.keyExportTransform(jwk)).toEqual(jwk);
        jwk = {foo: 'fighters'};
        expect(subtle.keyExportTransform(jwk)).toEqual(jwk);
    });
});