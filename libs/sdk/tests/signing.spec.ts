/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { ClientSecretCredential } from '@azure/identity';
import { CryptoFactoryManager, KeyStoreInMemory, Subtle, KeyStoreFactory, CryptoFactoryScope, KeyReference, JsonWebKey, CryptoFactory, CryptoFactoryNode, KeyType, KeyStoreOptions } from '../lib/index';
import Credentials from './Credentials';

describe('signing', () => {
    let originalTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
    beforeEach(async () => {
        jasmine.DEFAULT_TIMEOUT_INTERVAL = 60000;
    });

    afterEach(() => {
        jasmine.DEFAULT_TIMEOUT_INTERVAL = originalTimeout;
    });

    // Setup the default crypto factory
    const cryptoFactoryNode = CryptoFactoryManager.create('CryptoFactoryNode', new KeyStoreInMemory(), new Subtle());

    // Setup the key vault crypto factory.
    // Key vault needs your credentials. Put them in Credentials.ts
    const credentials = new ClientSecretCredential(Credentials.tenantGuid, Credentials.clientId, Credentials.clientSecret);
    const subtle = new Subtle();
    const keyVaultEnabled = Credentials.vaultUri.startsWith('https');
    const keyStoreKeyVault = KeyStoreFactory.create('KeyStoreKeyVault', credentials, Credentials.vaultUri, new KeyStoreInMemory());
    const cryptoFactoryKeyVault = CryptoFactoryManager.create(
        'CryptoFactoryKeyVault',
        keyStoreKeyVault,
        subtle);

    // Loop through these crypto factories. If no credentials for Key Vault are present, we skip key vault
    const factories = [cryptoFactoryNode];
    if (keyVaultEnabled) {
        factories.push(cryptoFactoryKeyVault);
    } else {
        console.log('Enter your key vault credentials in Credentials.ts to enable key vault testing')
    }

    it('should sign with secp256k1 with generated key', async () => {

        for (let inx = 0; inx < factories.length; inx++) {
            // Get the subtle api for private key operations
            const subtlePrivate = factories[inx].getMessageSigner('ECDSA', CryptoFactoryScope.Private, new KeyReference('', 'secret'));
            const isKeyVault = subtlePrivate.constructor.name === 'SubtleCryptoKeyVault'
            console.log(`Use subtle ${subtlePrivate.constructor.name}`);

            // Generate a secp256k1 key pair
            const algorithm = <EcKeyGenParams>{
                name: 'ECDSA',
                namedCurve: 'secp256k1'
            };
            const key: CryptoKeyPair = <CryptoKeyPair>await subtlePrivate.generateKey(
                algorithm,
                !isKeyVault,
                ['sign', 'verify']);

            // Export the key into JWK format. Only possible if key was generated with extractable = true, not possible on key vault
            if (!isKeyVault) {
                const jwk = await subtlePrivate.exportKey(
                    'jwk',
                    key.privateKey);
                console.log(`Exported private key: ${JSON.stringify(jwk)}`);
            }

            // Create ECDSA signature. In case of key vault, we only pass the key reference. 
            // Private key stays on key vault. 
            const signature = await subtlePrivate.sign(
                <EcdsaParams>{
                    name: 'ECDSA',
                    hash: { name: 'SHA-256' }
                },
                <CryptoKey>(isKeyVault ? key.publicKey : key.privateKey),
                Buffer.from('Payload to sign'));

            // Verify the signature
            //const cryptoKey = await subtle.importKey('jwk', jwk, algorithm, true,  ['sign', 'verify']);
            const result = await subtle.verify(
                <EcdsaParams>{
                    name: 'ECDSA',
                    hash: { name: 'SHA-256' }
                },
                key.publicKey,
                signature,
                Buffer.from('Payload to sign'));
            expect(result).toBeTruthy();

        }
    });

    it('should sign with secp256k1 imported key on key vault', async () => {

        if (!keyVaultEnabled) {
            console.log('This test only works on key vault. Add your key vault credentials to Credentials.ts');
            return;
        }

        // preparation to generate key and import this one in key vault
        const keyName = 'importedKey';

        // Generate a secp256k1 key pair
        const algorithm = <EcKeyGenParams>{
            name: 'ECDSA',
            namedCurve: 'secp256k1'
        };

        const keyPair: CryptoKeyPair = <CryptoKeyPair>await subtle.generateKey(
            algorithm,
            true,
            ['sign', 'verify']);

        const jwk = <JsonWebKey>await subtle.exportKey('jwk', keyPair.privateKey);

        // Save key in key vault as a key vault key
        const reference = new KeyReference(keyName, 'key');
        await keyStoreKeyVault.save(reference, jwk)


        // Get the subtle api for private key operations
        const subtleKv = cryptoFactoryKeyVault.getMessageSigner('ECDSA', CryptoFactoryScope.Private, reference);

        // retrieve key from key vault
        const kvJwk = (await keyStoreKeyVault.get(reference)).getKey<JsonWebKey>();

        // Get crypto key from JWK
        const key = <CryptoKey>await subtleKv.importKey(
            'jwk',
            kvJwk,
            algorithm,
            true,
            ['sign', 'verify']);

        // Create ECDSA signature. Reference subtleKv to use key on key vault.
        const signature = await subtleKv.sign(
            <EcdsaParams>{
                name: 'ECDSA',
                hash: { name: 'SHA-256' }
            },
            key,
            Buffer.from('Payload to sign'));

        // Verify the signature on subtle               
        const result = await subtle.verify(
            <EcdsaParams>{
                name: 'ECDSA',
                hash: { name: 'SHA-256' }
            },
            key,
            signature,
            Buffer.from('Payload to sign'));
        expect(result).toBeTruthy();
    });

    it('should sign with secp256k1 imported secret on key vault', async () => {
        
        if (!keyVaultEnabled) {
            console.log('This test only works on key vault. Add your key vault credentials to Credentials.ts');
            return;
        }

        // preparation to generate key and import this one in key vault
        const keyName = 'importedSecret';
        const reference = new KeyReference(keyName, 'secret');

        // Generate a secp256k1 key pair
        const algorithm = <EcKeyGenParams>{
            name: 'ECDSA',
            namedCurve: 'secp256k1'
        };

        const keyPair: CryptoKeyPair = <CryptoKeyPair>await subtle.generateKey(
            algorithm,
            true,
            ['sign', 'verify']);

        const jwk = <JsonWebKey>await subtle.exportKey('jwk', keyPair.privateKey);

        // Save key in key vault as a key vault secret
        await keyStoreKeyVault.save(reference, jwk)

        // Change Crypto factory
        const factory = new CryptoFactoryNode(keyStoreKeyVault, subtle);

        // Get the subtle api for private key operations
        const subtlePrivate = factory.getMessageSigner('ECDSA', CryptoFactoryScope.Private, reference);

        // retrieve key from key vault
        const kvJwk = (await keyStoreKeyVault.get(reference, new KeyStoreOptions({publicKeyOnly: false}))).getKey<JsonWebKey>();

        // Get crypto key from JWK
        const key = <CryptoKey>await subtlePrivate.importKey(
            'jwk',
            kvJwk,
            algorithm,
            true,
            ['sign', 'verify']);

        // Create ECDSA signature. Reference subtleKv to use key on key vault.
        const signature = await subtlePrivate.sign(
            <EcdsaParams>{
                name: 'ECDSA',
                hash: { name: 'SHA-256' }
            },
            key,
            Buffer.from('Payload to sign'));

        // Verify the signature on subtle               
        const result = await subtle.verify(
            <EcdsaParams>{
                name: 'ECDSA',
                hash: { name: 'SHA-256' }
            },
            key,
            signature,
            Buffer.from('Payload to sign'));
        expect(result).toBeTruthy();
    });
});
