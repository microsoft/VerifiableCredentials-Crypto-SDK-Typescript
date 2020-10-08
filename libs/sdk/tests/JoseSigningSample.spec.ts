/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { KeyReference, CryptoBuilder, KeyUse, IPayloadProtectionSigning, JoseBuilder, KeyStoreOptions, JsonWebKey, CryptoFactoryNode, KeyStoreKeyVault, KeyStoreInMemory, Subtle, LongFormDid } from '../lib/index';
import Credentials from './Credentials';
import { ClientSecretCredential } from '@azure/identity';

describe('Jose Signing', () => {
    const credentials = new ClientSecretCredential(Credentials.tenantGuid, Credentials.clientId, Credentials.clientSecret);
    const keyVaultEnabled = Credentials.vaultUri.startsWith('https');

    let originalTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
    beforeEach(async () => {
        jasmine.DEFAULT_TIMEOUT_INTERVAL = 60000;
    });

    afterEach(() => {
        jasmine.DEFAULT_TIMEOUT_INTERVAL = originalTimeout;
    });

    it('should sign and validate a message protected by JWS - ES256K', async () => {
        const payload = Buffer.from('Throughout human history, we have been dependent on machines to survive. Fate, it seems, is not without a sense of irony.');

        // Setup sample
        const keyReference = new KeyReference('neo');
        let crypto = new CryptoBuilder()
            .useSigningKeyReference(keyReference)
            .build();

        let jose: IPayloadProtectionSigning = new JoseBuilder(crypto)
            .build();

        // Generate and save a signing key
        crypto = await crypto.generateKey(KeyUse.Signature);


        // Sign the payload
        jose = await jose.sign(payload);

        // Serialize the signature
        const signature = await jose.serialize();

        // make sure to have a clean jose object
        jose = new JoseBuilder(crypto)
            .build();

        // Deserialize the received signature
        jose = await jose.deserialize(signature);

        const validated = await jose.verify();
        expect(validated).toBeTruthy();
    });

    it('should sign in key vault and validate a message protected by JWS - ES256K', async () => {


        if (!keyVaultEnabled) {
            console.log('This test only works on key vault. Add your key vault credentials to Credentials.ts');
            return;
        }

        const payload = Buffer.from('Throughout human history, we have been dependent on machines to survive. Fate, it seems, is not without a sense of irony.');

        // Setup sample
        const keyReference = new KeyReference('neo', 'key');
        let crypto = new CryptoBuilder()
            .useKeyVault(credentials, Credentials.vaultUri)
            .useSigningKeyReference(keyReference)
            .build();

        let jose: IPayloadProtectionSigning = new JoseBuilder(crypto)
            .build();

        // Generate and save a signing key
        crypto = await crypto.generateKey(KeyUse.Signature);


        // Sign the payload
        jose = await jose.sign(payload);

        // Serialize the signature
        const signature = await jose.serialize();

        // Deserialize the received signature
        jose = await jose.deserialize(signature);

        const validated = await jose.verify();
        expect(validated).toBeTruthy();
    });

    it('should sign in key vault with an imported key and validate a message protected by JWS - ES256K', async () => {


        if (!keyVaultEnabled) {
            console.log('This test only works on key vault. Add your key vault credentials to Credentials.ts');
            return;
        }

        const payload = Buffer.from('Throughout human history, we have been dependent on machines to survive. Fate, it seems, is not without a sense of irony.');

        // Setup sample
        const keyReference = new KeyReference('neo', 'secret');
        const subtle = new Subtle();
        const cryptoFactory = new CryptoFactoryNode(new KeyStoreKeyVault(credentials, Credentials.vaultUri, new KeyStoreInMemory()), subtle);
        let crypto = new CryptoBuilder()
            .useKeyVault(credentials, Credentials.vaultUri)
            .useCryptoFactory(cryptoFactory)
            .useSigningKeyReference(keyReference)
            .build();

        let jose: IPayloadProtectionSigning = new JoseBuilder(crypto)
            .build();

        // Simulate bring your own key which is generated on key vault
        // First generate a key

        crypto = await crypto.generateKey(KeyUse.Signature);


        // Sign the payload
        jose = await jose.sign(payload);

        // Serialize the signature
        const signature = await jose.serialize();

        // Deserialize the received signature
        jose = await jose.deserialize(signature);

        const validated = await jose.verify();
        expect(validated).toBeTruthy();
    });

    it('should sign and validate a message protected by JWS - EdDSA', async () => {
        const payload = Buffer.from(`What you know you can't explain, but you feel it. You've felt it your entire life, that there's something wrong with the world. You don't know what it is, but it's there, like a splinter in your mind, driving you mad.`);

        // Setup sample
        const keyReference = new KeyReference('morpheus');
        let crypto = new CryptoBuilder()
            .useSigningAlgorithm('EdDSA')
            .useSigningKeyReference(keyReference)
            .build();

        let jose: IPayloadProtectionSigning = new JoseBuilder(crypto)
            .build();

        // Generate and save a signing key
        crypto = await crypto.generateKey(KeyUse.Signature);


        // Sign the payload
        jose = await jose.sign(payload);

        // Serialize the signature
        const signature = await jose.serialize();

        // make sure to have a clean jose object
        jose = new JoseBuilder(crypto)
            .build();

        // Deserialize the received signature
        jose = await jose.deserialize(signature);

        const validated = await jose.verify();
        expect(validated).toBeTruthy();
    });

    it('should sign by a key stored in key vault and validate a message protected by JWS - EdDSA', async () => {


        if (!keyVaultEnabled) {
            console.log('This test only works on key vault. Add your key vault credentials to Credentials.ts');
            return;
        }

        const payload = Buffer.from(`What you know you can't explain, but you feel it. You've felt it your entire life, that there's something wrong with the world. You don't know what it is, but it's there, like a splinter in your mind, driving you mad.`);

        // Setup sample
        const keyReference = new KeyReference('morpheus', 'secret');
        const subtle = new Subtle();
        const cryptoFactory = new CryptoFactoryNode(new KeyStoreKeyVault(credentials, Credentials.vaultUri, new KeyStoreInMemory()), subtle);
        let crypto = new CryptoBuilder()
            .useSigningAlgorithm('EdDSA')
            .useKeyVault(credentials, Credentials.vaultUri)
            .useCryptoFactory(cryptoFactory)
            .useSigningKeyReference(keyReference)
            .build();

        let jose: IPayloadProtectionSigning = new JoseBuilder(crypto)
            .build();

        // Generate and save a signing key
        crypto = await crypto.generateKey(KeyUse.Signature);

        // Sign the payload
        jose = await jose.sign(payload);

        // Serialize the signature
        const signature = await jose.serialize();

        // Deserialize the received signature
        jose = await jose.deserialize(signature);

        const validated = await jose.verify();
        expect(validated).toBeTruthy();
    });

    it('should sign in key vault with an imported key and validate a message protected by JWS - ES256K', async () => {


        if (!keyVaultEnabled) {
            console.log('This test only works on key vault. Add your key vault credentials to Credentials.ts');
            return;
        }

        const payload = Buffer.from('Throughout human history, we have been dependent on machines to survive. Fate, it seems, is not without a sense of irony.');

        // Setup sample
        const keyReference = new KeyReference('neo', 'secret');
        const subtle = new Subtle();
        const cryptoFactory = new CryptoFactoryNode(new KeyStoreKeyVault(credentials, Credentials.vaultUri, new KeyStoreInMemory()), subtle);
        let crypto = new CryptoBuilder()
            .useKeyVault(credentials, Credentials.vaultUri)
            .useCryptoFactory(cryptoFactory)
            .useSigningKeyReference(keyReference)
            .build();

        let jose: IPayloadProtectionSigning = new JoseBuilder(crypto)
            .build();

        // Simulate bring your own key which is generated on key vault
        // First generate a key

        crypto = await crypto.generateKey(KeyUse.Signature);


        // Sign the payload
        jose = await jose.sign(payload);

        // Serialize the signature
        const signature = await jose.serialize();

        // Deserialize the received signature
        jose = await jose.deserialize(signature);

        const validated = await jose.verify();
        expect(validated).toBeTruthy();
    });

});