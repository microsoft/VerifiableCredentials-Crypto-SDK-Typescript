/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { KeyStoreInMemory } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import { KeyStoreKeyVault, SubtleCryptoKeyVault } from '../src';
import { ClientSecretCredential } from '@azure/identity';
import { Subtle } from 'verifiablecredentials-crypto-sdk-typescript-plugin';
import Credentials from './Credentials';

describe('SubtleCryptoKeyVault', () => {
    // Sample config
    const tenantId = Credentials.tenantGuid;
    const clientId = Credentials.clientId;
    const clientSecret = encodeURI(Credentials.clientSecret);
    const vaultUri = Credentials.vaultUri;
    const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
    const keyVaultEnable = vaultUri.startsWith('https://');

    const cache = new KeyStoreInMemory();
    const keyStore = new KeyStoreKeyVault(credential, vaultUri, cache);
    const subtle = new Subtle();
    const subtleKv: any = new SubtleCryptoKeyVault(subtle, keyStore);

    if (!keyVaultEnable) {
        console.log('Key vault is not enabled. Add your credentials to Credentials.ts')
        return;
    }

    const genKey = async () => {
        const cryptoKey = await subtleKv.generateKey(<EcKeyGenParams>{ name: "ECDSA", hash: { name: "SHA-256" }, namedCurve: 'secp256k1' }, true, ["sign", "verify"]);
        return cryptoKey;
    }

    it('should create instance', () => {
        let subtleKv: any = new SubtleCryptoKeyVault(subtle, keyStore);
        expect(subtleKv.getSubtleCrypto().constructor.name).toEqual('SubtleCryptoKeyVault');
    });

    it('should generate key', async () => {
        const cryptoKey = await genKey();
        expect(cryptoKey).toBeDefined();
    });

    it('should test algorithmTransform', () => {
        let alg: any = {test: 'name'};
        expect(subtleKv.algorithmTransform(alg)).toEqual(alg);
        alg = {foo: 'fighters'};
        expect(subtleKv.algorithmTransform(alg)).toEqual(alg);
    });
    it('should test keyImportTransform', () => {
        let jwk: any = { test: 'name' };
        expect(subtleKv.keyImportTransform(jwk)).toEqual(jwk);
        jwk = { foo: 'fighters' };
        expect(subtleKv.keyImportTransform(jwk)).toEqual(jwk);
        jwk = { crv: 'P-256K' };
        expect(subtleKv.keyImportTransform(jwk)).toEqual({ crv: 'SECP256K1' });
        jwk = { crv: 'SECP256K1' };
        expect(subtleKv.keyImportTransform(jwk)).toEqual({ crv: 'SECP256K1' });
        jwk = { crv: 'XXX' };
        expect(subtleKv.keyImportTransform(jwk)).toEqual({ crv: 'XXX' });

    });
    it('should test keyExportTransform', () => {
        let jwk: any = { test: 'name' };
        expect(subtleKv.keyExportTransform(jwk)).toEqual(jwk);
        jwk = { foo: 'fighters' };
        expect(subtleKv.keyExportTransform(jwk)).toEqual(jwk);
        jwk = { crv: 'P-256K' };
        expect(subtleKv.keyExportTransform(jwk)).toEqual({ crv: 'SECP256K1' });
        jwk = { crv: 'K-256' };
        expect(subtleKv.keyExportTransform(jwk)).toEqual({ crv: 'SECP256K1' });
        jwk = { crv: 'SECP256K1' };
        expect(subtleKv.keyExportTransform(jwk)).toEqual({ crv: 'SECP256K1' });
    });
});