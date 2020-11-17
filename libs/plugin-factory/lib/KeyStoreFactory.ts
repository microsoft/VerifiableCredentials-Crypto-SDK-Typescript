/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { TokenCredential } from '@azure/identity';
import { CryptoError, IKeyStore, KeyStoreInMemory } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import { KeyStoreKeyVault } from 'verifiablecredentials-crypto-sdk-typescript-plugin-keyvault';
import LRUCache from 'lru-cache';

/**
 * Key store factory
 */
export default class KeyStoreFactory {

  private static sessionCache: LRUCache<string, KeyStoreKeyVault> = new LRUCache<string, KeyStoreKeyVault>({ maxAge: 1000 * 24 * 3600, max: 10000, stale: true });

  /**
   * Create the key store instance
   * @param cryptoFactoryName The name of the crypto factory.
   * @param credential The azure token credential
   * @param vaultUri of the key vault endpoint
    */
  public static create(keyStoreName: string, credential?: TokenCredential, vaultUri?: string, cache?: IKeyStore): IKeyStore {
    switch (keyStoreName) {
      case 'KeyStoreInMemory':
        return new KeyStoreInMemory();
      case 'KeyStoreKeyVault':
        if (!cache) {
          cache = new KeyStoreInMemory();
        }
        // Check for cached version
        let keyStoreVault = KeyStoreFactory.sessionCache.get(vaultUri!);
        if (keyStoreVault) {
          return keyStoreVault;
        }

        keyStoreVault = new KeyStoreKeyVault(credential!, vaultUri!, cache);
        KeyStoreFactory.sessionCache.set(vaultUri!, keyStoreVault);
        return keyStoreVault;
      default:
        throw new CryptoError(<any>undefined, `Key store '${keyStoreName}' not found`);
    }
  }
}
