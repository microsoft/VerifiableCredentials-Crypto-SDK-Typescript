/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { KeyStoreInMemory } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import { CryptoFactoryManager, SubtleCryptoFactory } from '../lib/index';

describe('CryptoFactoryManager', () => {
  const crypto = SubtleCryptoFactory.create('SubtleCryptoNode');
  const keyStore = new KeyStoreInMemory();

  it('should create CryptoFactoryNode', () => {
    const cryptoFactory = CryptoFactoryManager.create('CryptoFactoryNode', keyStore, crypto);
    expect(cryptoFactory.constructor.name).toEqual('CryptoFactoryNode');

    // negative cases
    expect(() => CryptoFactoryManager.create('xxx', keyStore, crypto)).toThrowError(`Crypto factory 'xxx' not found`)  });

  it('should create CryptoFactoryKeyVault', () => {
    const cryptoFactory = CryptoFactoryManager.create('CryptoFactoryKeyVault', keyStore, crypto);
    expect(cryptoFactory.constructor.name).toEqual('CryptoFactoryKeyVault');
  });
});


