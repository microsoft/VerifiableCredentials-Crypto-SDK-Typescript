import { CryptoFactoryBrowser, SubtleCryptoNode } from '../lib';
import { KeyStoreInMemory } from '@microsoft/crypto-keystore';

describe('CryptoFactoryBrowser', () => {
    it('should create a CryptoFactoryBrowser', () => {
        const keyStore = new KeyStoreInMemory();
        const factory = new CryptoFactoryBrowser(keyStore, SubtleCryptoNode.getSubtleCrypto());
        expect(factory).toBeDefined();
    });
});