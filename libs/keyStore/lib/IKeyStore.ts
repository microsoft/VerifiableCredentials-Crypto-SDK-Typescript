/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { IKeyContainer, KeyType, CryptographicKey } from 'verifiablecredentials-crypto-sdk-typescript-keys';
import KeyStoreOptions from './KeyStoreOptions';
import { KeyReference } from '.';

/**
 * Define an item in the key store list
 */
export interface KeyStoreListItem {
  /**
   * The kid's of the key versions
   */
  kids: string[];

  /**
   * The key type of the key version
   */
  kty: KeyType;
}

/**
 * Define different types for the algorithm parameter
 */
export type CryptoAlgorithm = RsaPssParams | EcdsaParams | Algorithm;

/**
 * Interface defining methods and properties to
 * be implemented by specific key stores.
 */
export default interface IKeyStore {
  /**
   * Returns the key container associated with the specified
   * key reference.
   * @param keyIdentifier for which to return the key.
   * @param [options] Options for retrieving.
   */
  get (keyReference: KeyReference, options?: KeyStoreOptions): Promise<IKeyContainer>;

  /**
   * Saves the specified key container to the key store using
   * the key reference.
   * @param keyReference Reference for the key being saved.
   * @param key being saved to the key store.
   * @param [options] Options for saving.
   */
  save (keyReference: KeyReference, key: CryptographicKey | string, options?: KeyStoreOptions): Promise<void>;

  /**
   * Lists all key references with their corresponding key ids
   * @param [options] Options for listing.
   */
  list (type?: string, options?: KeyStoreOptions): Promise<{ [name: string]: KeyStoreListItem }>;
}
