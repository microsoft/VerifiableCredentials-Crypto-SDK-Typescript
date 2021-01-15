import { ClientSecretCredential } from '@azure/identity';
import { KeyReference, KeyStoreInMemory } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import { CryptoFactoryScope, Subtle } from 'verifiablecredentials-crypto-sdk-typescript-plugin';
import { CryptoFactoryKeyVault, KeyStoreKeyVault } from '../src';

describe('CryptoFactoryKeyVault', () => {
    it('should create a CryptoFactoryKeyVault', () => {
        const cache = new KeyStoreInMemory();
        const credential = new ClientSecretCredential('tenant', 'clientid', 'secret');
        const keyStore = new KeyStoreKeyVault(credential, 'https://example.vault.com', cache);
        const subtle = new Subtle();
    
        const crypto = new CryptoFactoryKeyVault(keyStore, subtle);
        expect(crypto.getMessageSigner('ES256K', CryptoFactoryScope.Private, new KeyReference('key', 'key')).constructor.name).toEqual('SubtleCryptoKeyVault');
        expect(crypto.getMessageSigner('ECDSA', CryptoFactoryScope.Private, new KeyReference('key', 'key')).constructor.name).toEqual('SubtleCryptoKeyVault');
        expect(crypto.getKeyEncrypter('RSA-OAEP-256', CryptoFactoryScope.Private, new KeyReference('key', 'key')).constructor.name).toEqual('SubtleCryptoKeyVault');
        expect(crypto.getKeyEncrypter('RSA-OAEP', CryptoFactoryScope.Private, new KeyReference('key', 'key')).constructor.name).toEqual('SubtleCryptoKeyVault');
        expect(crypto.getMessageSigner('RSASSA-PKCS1-v1_5', CryptoFactoryScope.Private, new KeyReference('key', 'key')).constructor.name).toEqual('Subtle');
    })
});