/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { SubtleCryptoNode, CryptoFactory, CryptoFactoryScope, CryptoHelpers, SubtleCryptoExtension } from '../lib';
import { KeyStoreInMemory, KeyReference } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import EcPrivateKey from 'verifiablecredentials-crypto-sdk-typescript-keys/dist/lib/ec/EcPrivateKey';
import { PublicKey, JsonWebKey } from 'verifiablecredentials-crypto-sdk-typescript-keys';
import base64url from 'base64url';

describe('SubtleCryptoNode', () => {
    it('should create instance', () => {
        let subtle: any = new SubtleCryptoNode();
        expect(subtle.crypto.constructor.name).toEqual('Subtle');
        expect(subtle.getSubtleCrypto().constructor.name).toEqual('Subtle');
        expect(SubtleCryptoNode.getSubtleCrypto().constructor.name).toEqual('Subtle');
    });
    it('should test algorithmTransform', () => {
        let subtle: any = new SubtleCryptoNode();
        let alg: any = {test: 'name'};
        expect(subtle.algorithmTransform(alg)).toEqual(alg);
        alg = {foo: 'fighters'};
        expect(subtle.algorithmTransform(alg)).toEqual(alg);
    });
    it('should test keyImportTransform', () => {
        let subtle: any = new SubtleCryptoNode();
        let jwk: any = {test: 'name'};
        expect(subtle.keyImportTransform(jwk)).toEqual(jwk);
        jwk = {foo: 'fighters'};
        expect(subtle.keyImportTransform(jwk)).toEqual(jwk);
    });
    it('should test keyExportTransform', () => {
        let subtle: any = new SubtleCryptoNode();
        let jwk: any = {test: 'name'};
        expect(subtle.keyExportTransform(jwk)).toEqual(jwk);
        jwk = {foo: 'fighters'};
        expect(subtle.keyExportTransform(jwk)).toEqual(jwk);
    });
});