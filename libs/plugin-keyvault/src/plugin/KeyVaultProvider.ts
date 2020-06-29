/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { KeyClient, JsonWebKey, KeyType } from '@azure/keyvault-keys';
import { Subtle } from 'verifiablecredentials-crypto-sdk-typescript-plugin';
import { ProviderCrypto, CryptoKey } from 'webcrypto-core';
import { IKeyStore, KeyStoreOptions } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
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
    public subtle: Subtle,
    public keyStore: IKeyStore) {
    super();
  }

  /**
   * Generate key pair
   * @param algorithm for key generation
   * @param extractable is true if the key is exportable
   * @param keyUsages sign or verify
   */
  async generate(kty: KeyType, algorithm: Algorithm, _extractable: boolean, keyUsages: KeyUsage[], options?: any): Promise<object> {
    let name: string = this.generateKeyName(algorithm, keyUsages, kty);
    if (options && options.name) {
      name = options.name;
    }

    const client = <KeyClient>(<KeyStoreKeyVault>this.keyStore).getKeyStoreClient(KeyStoreKeyVault.KEYS);
    const publicKey = await client.createKey(name, kty, options);
    return publicKey;
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

  /**
   * Convert to CryptoKey
   * @param algorithm for key generation
   * @param extractable is true if the key is exportable
   * @param keyUsages sign or verify
   * @param key to convert
   */
  public async toCryptoKey(algorithm: Algorithm, type: 'public' | 'private', extractable: boolean, keyUsages: KeyUsage[], key: any): Promise<CryptoKey> {
    const cryptoKey: any = CryptoKey.create(algorithm, type, extractable, keyUsages);
    cryptoKey.key = key;
    return cryptoKey;
  }

  /**
   * Convert to CryptoKeyPair
   * @param algorithm for key generation
   * @param extractable is true if the key is exportable
   * @param keyUsages sign or verify
   * @param key to convert
   */
  public async toCryptoKeyPair(algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[], key: any): Promise<CryptoKeyPair> {
    const cryptoKey = await this.toCryptoKey(algorithm, 'public', extractable, keyUsages, key);
    const pair = {
      publicKey: cryptoKey
    };
    return <CryptoKeyPair>pair;
  }

}
