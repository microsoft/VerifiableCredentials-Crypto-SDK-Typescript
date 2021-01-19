/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { CryptoBuilder, CryptoFactory, KeyStoreFactory, Subtle, KeyUse, KeyStoreOptions, KeyReference } from '../lib/index';
import { ClientSecretCredential } from '@azure/identity';

describe('CryptoBuilder', () => {
    it ('should create a builder', () =>{
        let builder = new CryptoBuilder();
        expect(builder.cryptoFactory.constructor.name).toEqual('CryptoFactoryNode');
        expect(builder.keyStore.constructor.name).toEqual('KeyStoreInMemory');
        expect(builder.subtle.constructor.name).toEqual('Subtle');
        expect(builder.signingKeyReference.keyReference).toEqual('signing-ES256K');
        expect(builder.signingAlgorithm).toEqual('ES256K');
        expect(builder.recoveryKeyReference.keyReference).toEqual('recovery-ES256K');
        expect(builder.recoveryAlgorithm).toEqual('ES256K');
        expect(builder.signingKeyIsExtractable).toBeTruthy();

        builder.useSigningAlgorithm('EdDSA');
        expect(builder.signingAlgorithm).toEqual('EdDSA');
        builder.useRecoveryAlgorithm('EdDSA');
        expect(builder.recoveryAlgorithm).toEqual('EdDSA');
        builder.useUpdateAlgorithm('EdDSA');
        expect(builder.updateAlgorithm).toEqual('EdDSA');
        builder = new CryptoBuilder();

        builder.useDid('did');
        expect(builder.did).toEqual('did');
        
        const credential = new ClientSecretCredential('tenantId', 'clientId', 'clientSecret');
        const vault = 'https://keyvault.com';
        const cryptoFactory = new CryptoFactory(KeyStoreFactory.create('KeyStoreKeyVault', credential, vault), new Subtle());
        const cfBuilder  = builder.useCryptoFactory(cryptoFactory);
        expect(cfBuilder.cryptoFactory).toEqual(cryptoFactory);

        builder = builder.useKeyVault(credential, vault);
        expect(builder.cryptoFactory.keyStore.constructor.name).toEqual('KeyStoreKeyVault');
        expect(builder.signingKeyIsExtractable).toBeTruthy();
        expect(builder.recoveryKeyIsExtractable).toBeTruthy();
        expect(builder.updateKeyIsExtractable).toBeTruthy();
        expect(builder.signingKeyReference).toEqual(new KeyReference('signing-ES256K', 'secret'));
        expect(builder.recoveryKeyReference).toEqual(new KeyReference('recovery-ES256K', 'secret'));
        expect(builder.updateKeyReference).toEqual(new KeyReference('update-ES256K', 'secret'));

        expect(builder.signingKeyReference.cryptoKey).toBeUndefined();
        builder = builder.useSigningKeyReference(new KeyReference('signing', 'key'));
        expect(builder.signingKeyReference?.keyReference).toEqual('signing');
        expect(builder.signingKeyIsExtractable).toBeFalsy();
        expect(builder.signingKeyOptions.latestVersion).toBeTruthy();
        expect(builder.signingKeyOptions.publicKeyOnly).toBeFalsy();
        builder = builder.useSigningKeyReference(new KeyReference('signing', 'secret'));
        expect(builder.signingKeyIsExtractable).toBeTruthy();

        builder = builder.useRecoveryKeyReference(new KeyReference('recovery', 'key'));
        expect(builder.recoveryKeyReference?.keyReference).toEqual('recovery');
        expect(builder.recoveryKeyIsExtractable).toBeFalsy();
        expect(builder.recoveryKeyOptions.latestVersion).toBeTruthy();
        expect(builder.recoveryKeyOptions.publicKeyOnly).toBeFalsy();
        builder = builder.useRecoveryKeyReference(new KeyReference('update', 'secret'));
        expect(builder.recoveryKeyIsExtractable).toBeTruthy();

        builder = builder.useUpdateKeyReference(new KeyReference('update', 'key'));
        expect(builder.updateKeyReference?.keyReference).toEqual('update');
        expect(builder.updateKeyIsExtractable).toBeFalsy();
        expect(builder.updateKeyOptions.latestVersion).toBeTruthy();
        expect(builder.updateKeyOptions.publicKeyOnly).toBeFalsy();
        builder = builder.useUpdateKeyReference(new KeyReference('update', 'secret'));
        expect(builder.updateKeyIsExtractable).toBeTruthy();

        const crypto = builder.build();
        expect(crypto.builder).toEqual(builder);
    });

    it('should generate a signing key', async () => {
        let crypto = new CryptoBuilder()
            .useSigningKeyReference(new KeyReference('signingKey'))
            .useSigningAlgorithm('RS256')
            .build();
        crypto = await crypto.generateKey(KeyUse.Signature);
        const jwk = await crypto.builder.keyStore.get(crypto.builder.signingKeyReference!);
        expect(jwk.alg).toEqual('RS256');
    });

    it('should generate a recovery key', async () => {
        let crypto = new CryptoBuilder()
            .useRecoveryKeyReference(new KeyReference('recoveryKey'))
            .useRecoveryAlgorithm('RS256')
            .build();
        crypto = await crypto.generateKey(KeyUse.Signature, 'recovery');
        const jwk = await crypto.builder.keyStore.get(crypto.builder.recoveryKeyReference!);
        expect(jwk.alg).toEqual('RS256');
    });

    it('should generate an update key', async () => {
        let crypto = new CryptoBuilder()
            .useUpdateKeyReference(new KeyReference('updateKey'))
            .useUpdateAlgorithm('RS256')
            .build();
        crypto = await crypto.generateKey(KeyUse.Signature, 'update');
        const jwk = await crypto.builder.keyStore.get(crypto.builder.updateKeyReference!);
        expect(jwk.alg).toEqual('RS256');
    });
});