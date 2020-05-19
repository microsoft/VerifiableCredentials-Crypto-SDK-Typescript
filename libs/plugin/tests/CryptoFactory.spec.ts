/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { SubtleCryptoNode, CryptoFactory, CryptoFactoryNode, CryptoFactoryScope } from '../lib/index';
import { KeyStoreInMemory } from '@microsoft/crypto-keystore';
//import { SubtleCryptoElliptic } from '../../';

describe('CryptoFactory', () => {
  it('should create a crypto suite',() => {
    const keyStore = new KeyStoreInMemory();
    
    const factory = new CryptoFactory(keyStore, SubtleCryptoNode.getSubtleCrypto());
    expect(factory).toBeDefined();
    const keyEncrypter = factory.getKeyEncrypter('*', CryptoFactoryScope.All);
    expect(keyEncrypter).toBeDefined();
    const macSigner = factory.getMessageAuthenticationCodeSigner('*', CryptoFactoryScope.All);
    expect(macSigner).toBeDefined();
    const messageDigest = factory.getMessageDigest('*', CryptoFactoryScope.All);
    expect(messageDigest).toBeDefined();
    const messageSigner = factory.getMessageSigner('*', CryptoFactoryScope.All);
    expect(messageSigner).toBeDefined();
    const sharedKeyEncrypter = factory.getSharedKeyEncrypter('*', CryptoFactoryScope.All);
    expect(sharedKeyEncrypter).toBeDefined();
    const symmetricEncrypter = factory.getSymmetricEncrypter('*', CryptoFactoryScope.All);
    expect(symmetricEncrypter).toBeDefined();
  })

  it('should plugin a new algorithm into crypto suite',() => {
    const keyStore = new KeyStoreInMemory();
    
    const factory = new CryptoFactoryNode(keyStore, SubtleCryptoNode.getSubtleCrypto());
    const messageSigner = factory.getMessageSigner('ed25519', CryptoFactoryScope.All);
    //expect(messageSigner instanceof SubtleCryptoElliptic).toBeTruthy();
    expect((<any>messageSigner).providers.algorithms.includes('EDDSA')).toBeTruthy();
    expect((<any>messageSigner).providers.algorithms.includes('ECDSA')).toBeTruthy();
  })
});
