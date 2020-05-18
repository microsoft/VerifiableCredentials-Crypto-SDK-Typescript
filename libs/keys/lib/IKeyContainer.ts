/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { KeyUse } from './KeyUseFactory';
import { KeyType } from './KeyTypeFactory';
import SecretKey from './SecretKey';
import PrivateKey from './PrivateKey';
import PublicKey from './PublicKey';
import { JsonWebKey } from '.';

/**
 * List of types for keys
 */
export type CryptographicKey = SecretKey | PrivateKey | PublicKey | JsonWebKey;

/**
 * Represents a Key container in JWK format.
 * A key container will hold different versions of JWK keys.
 * Each key in the key container is the same type and usage
 */
export default interface IKeyContainer {
  /**
   * Key type
   */
  kty: KeyType;

  /**
   * Intended use
   */
  use: KeyUse | undefined;

  /**
   * Algorithm intended for use with this key
   */
  alg: string | undefined;

   /**
    * Return all keys in the container
    */
  keys: CryptographicKey[];

   /**
    * Get the default key from the key container
    */
  getKey<T> (): T;

  /**
   * Algorithm intended for use with this key
   */
  add (key: CryptographicKey): void;

  /**
   * True if private key is a remote key
   */
  remotekey (): boolean;
}
