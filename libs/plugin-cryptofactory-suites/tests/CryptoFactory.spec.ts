/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { SubtleCryptoNode, CryptoFactoryScope } from 'verifiablecredentials-crypto-sdk-typescript-plugin';
import { KeyStoreInMemory, KeyReference } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import { CryptoFactoryNode } from '../lib/index';

describe('CryptoFactory', () => {
  it('should plugin a new algorithm into crypto suite',() => {
    const keyStore = new KeyStoreInMemory();
    
    const factory = new CryptoFactoryNode(keyStore, SubtleCryptoNode.getSubtleCrypto());
    const messageSigner = factory.getMessageSigner('ed25519', CryptoFactoryScope.All, new KeyReference('', 'secret'));
    expect((<any>messageSigner).providers.algorithms.includes('EDDSA')).toBeTruthy();
    expect((<any>messageSigner).providers.algorithms.includes('ECDSA')).toBeTruthy();
  })
});
