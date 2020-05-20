/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { KeyClient, JsonWebKey, KeyType } from '@azure/keyvault-keys';
import { SubtleCrypto } from '@microsoft/crypto-subtle-plugin';
import { ProviderCrypto } from 'webcrypto-core';
import { IKeyStore, KeyStoreOptions } from '@microsoft/crypto-keystore';
import KeyStoreKeyVault from '../keyStore/KeyStoreKeyVault';

/**
 * Wrapper class for key vault plugin
 */
export default abstract class KeyVaultProvider extends ProviderCrypto {

  /**
   * Create a new instance of @class KeyVaultProvider
   * @param crypto A default subtle crypto object. Can be used for local crypto functions
   * @param keyStore The key vault key store
   */
  constructor(
    public subtle: SubtleCrypto,
    public keyStore: IKeyStore) {
    super();
  }

  /**
   * Generate key pair
   * @param algorithm for key generation
   * @param extractable is true if the key is exportable
   * @param keyUsages sign or verify
   */
  async generate(kty: KeyType, algorithm: Algorithm, _extractable: boolean, keyUsages: KeyUsage[], options?: any): Promise<JsonWebKey> {
    let name: string = this.generateKeyName(algorithm, keyUsages, kty);
    if (options && options.name) {
      name = options.name;
    }

    const client = <KeyClient>(<KeyStoreKeyVault>this.keyStore).getKeyStoreClient(new KeyStoreOptions({ extractable: false }));
    const keyPair = await client.createKey(name, kty, options);
    return (<any>keyPair).key as JsonWebKey;
  }

  /**
   * Set name for key
   * @param algorithm for name
   * @param keyUsages for name
   * @param keyType for name
   */
  generateKeyName(algorithm: Algorithm, keyUsages: KeyUsage[], keyType: string): string {
    return `${algorithm.name}-${keyUsages[0]}-${keyType}`;
  }
}
