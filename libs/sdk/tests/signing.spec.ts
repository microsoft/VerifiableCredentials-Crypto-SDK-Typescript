/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { ClientSecretCredential } from '@azure/identity';
import { CryptoFactoryManager, KeyStoreInMemory, Subtle, KeyStoreFactory, CryptoFactoryScope } from '../lib/index';
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
    const cryptoFactoryKeyVault = CryptoFactoryManager.create(
        'CryptoFactoryKeyVault',
        KeyStoreFactory.create('KeyStoreKeyVault', credentials, Credentials.vaultUri, new KeyStoreInMemory()),
        new Subtle());

    // Loop through these crypto factories. If no credentials for Key Vault are present, we skip key vault
    const factories = [cryptoFactoryNode];
    if (Credentials.vaultUri.startsWith('https')) {
        factories.push(cryptoFactoryKeyVault);
    }

    it('should sign with secp256k1', async () => {

        for (let inx = 0 ; inx < factories.length; inx++) {
            // Get the subtle api for private key operations
            const subtlePrivate = factories[inx].getMessageSigner('ECDSA', CryptoFactoryScope.Private);
            const isKeyVault = subtlePrivate.constructor.name === 'SubtleCryptoKeyVault'
            console.log(`Use subtle ${subtlePrivate.constructor.name}`);

            // Get the subtle api for public key operations
            const subtle = factories[inx].defaultCrypto;

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
                <CryptoKey> (isKeyVault ? key.publicKey : key.privateKey),
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
});
