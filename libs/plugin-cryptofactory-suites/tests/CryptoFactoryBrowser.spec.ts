import { SubtleCryptoNode } from 'verifiablecredentials-crypto-sdk-typescript-plugin';
import { KeyStoreInMemory } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import CryptoFactoryBrowser from '../lib/CryptoFactoryBrowser';

describe('CryptoFactoryBrowser', () => {
    it('should create a CryptoFactoryBrowser', () => {
        const keyStore = new KeyStoreInMemory();
        const factory = new CryptoFactoryBrowser(keyStore, SubtleCryptoNode.getSubtleCrypto());
        expect(factory).toBeDefined();
    });
});