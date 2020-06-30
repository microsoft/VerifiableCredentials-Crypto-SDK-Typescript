/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { CryptoBuilder, CryptoFactory, KeyStoreFactory, Subtle, KeyUse, KeyStoreOptions, KeyReference } from '../lib/index';
import { ClientSecretCredential } from '@azure/identity';

describe('CryptoBuilder', () => {
    it ('should create a builder', () =>{
        let builder = new CryptoBuilder();
        expect(builder.cryptoFactory.constructor.name).toEqual('CryptoFactory');
        expect(builder.keyStore.constructor.name).toEqual('KeyStoreInMemory');
        expect(builder.payloadProtectionProtocol.constructor.name).toEqual('Jose');
        expect(builder.subtle.constructor.name).toEqual('Subtle');
        expect(builder.signingKeyReference).toBeUndefined();
        expect(builder.signingAlgorithm).toEqual('ES256K');

        builder.useSigningAlgorithm('RSA-OAEP');
        expect(builder.signingAlgorithm).toEqual('RSA-OAEP');

        const credential = new ClientSecretCredential('tenantId', 'clientId', 'clientSecret');
        const vault = 'https://keyvault.com';
        const cryptoFactory = new CryptoFactory(KeyStoreFactory.create('KeyStoreKeyVault', credential, vault), new Subtle());
        const cfBuilder  = builder.useCryptoFactory(cryptoFactory);
        expect(cfBuilder.cryptoFactory).toEqual(cryptoFactory);

        builder = builder.useKeyVault(credential, vault);
        expect(builder.cryptoFactory.keyStore.constructor.name).toEqual('KeyStoreKeyVault');

        builder = builder.useSigningKeyReference(new KeyReference('signing', 'key'));
        expect(builder.signingKeyReference?.keyReference).toEqual('signing');
        expect(builder.signingKeyIsExtractable).toBeFalsy();
        expect(builder.signingKeyOptions.latestVersion).toBeTruthy();
        expect(builder.signingKeyOptions.publicKeyOnly).toBeFalsy();

        const crypto = builder.build();
        expect(crypto.builder).toEqual(builder);

    });

    it('should generate a signing key', async () => {
        let crypto = new CryptoBuilder()
            .useSigningKeyReference(new KeyReference('signingKey'))
            .useSigningAlgorithm('Rs256')
            .build();
        crypto = await crypto.generateKey(KeyUse.Signature);
        const jwk = await crypto.builder.keyStore.get(crypto.builder.signingKeyReference!);
        expect(jwk.alg).toEqual('RS256');
    });
});