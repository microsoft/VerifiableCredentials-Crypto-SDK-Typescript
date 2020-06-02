import { ClientSecretCredential } from '@azure/identity';
import { CryptoFactoryManager, KeyStoreInMemory, SubtleCrypto, KeyStoreFactory, CryptoFactory, CryptoFactoryScope } from '../src/index';
import Credentials from './Credentials';
import { isWorker } from 'cluster';

describe('signing', () => {
    let originalTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
    beforeEach(async () => {
        jasmine.DEFAULT_TIMEOUT_INTERVAL = 60000;
      });
      
      afterEach(() => {
        jasmine.DEFAULT_TIMEOUT_INTERVAL = originalTimeout;
      });
      
    // Setup the default crypto factory
    const cryptoFactoryNode = CryptoFactoryManager.create('CryptoFactoryNode', new KeyStoreInMemory(), new SubtleCrypto());

    // Setup the key vault crypto factory.
    // Key vault needs your credentials. Put them in Credentials.ts
    const credentials = new ClientSecretCredential(Credentials.tenantGuid, Credentials.clientId, Credentials.clientSecret);
    const cryptoFactoryKeyVault = CryptoFactoryManager.create(
        'CryptoFactoryKeyVault',
        KeyStoreFactory.create('KeyStoreKeyVault', credentials, Credentials.vaultUri, new KeyStoreInMemory()),
        new SubtleCrypto());

    // Loop through these crypto factories. If no credentials for Key Vault are present, we skip key vault
    const factories = [cryptoFactoryNode];
    if (Credentials.vaultUri.startsWith('https')) {
        factories.push(cryptoFactoryKeyVault);
    }

    it('should sign with secp256k1', async () => {

        for (let inx = 0 ; inx < factories.length; inx++) {
            // Get the subtle api for private key operations
            const subtleSecure = factories[inx].getMessageSigner('ECDSA', CryptoFactoryScope.Private);
            const isKeyVault = subtleSecure.constructor.name === 'SubtleCryptoKeyVault'
            console.log(`Use subtle ${subtleSecure.constructor.name}`);

            // Get the subtle api for public key operations
            const subtle = factories[inx].defaultCrypto;

            // Generate a secp256k1 key pair
            const algorithm = <EcKeyGenParams>{
                name: 'ECDSA',
                namedCurve: 'secp256k1'
            };
            const key: CryptoKeyPair = <CryptoKeyPair>await subtleSecure.generateKey(
                algorithm,
                true,
                ['sign', 'verify']);

            // Export the key into JWK format. Only possible if key was generated with extractable = true, not possible on key vault
            if (!isKeyVault) {
                const jwk = await subtleSecure.exportKey(
                    'jwk',
                    (<CryptoKeyPair>key).privateKey);
                console.log(`Exported private key: ${JSON.stringify(jwk)}`);
            }

            const jwk = await subtleSecure.exportKey(
                'jwk',
                (<CryptoKeyPair>key).publicKey);

            // Create ECDSA signature. In case of key vault, we only pass the key reference. 
            // Private key stays on key vault. 
            const signature = await subtleSecure.sign(
                <EcdsaParams>{
                    name: 'ECDSA',
                    hash: { name: 'SHA-256' }
                },
                <CryptoKey> (isKeyVault ? key.publicKey : key.privateKey),
                Buffer.from('Payload to sign'));

            // Verify the signature
            const cryptoKey = await subtle.importKey('jwk', jwk, algorithm, true,  ['sign', 'verify']);
            const result = await subtle.verify(
                <EcdsaParams>{
                    name: 'ECDSA',
                    hash: { name: 'SHA-256' }
                },
                cryptoKey,
                signature,
                Buffer.from('Payload to sign'));
            expect(result).toBeTruthy();

        }
    });
});
