/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { KeyUse } from './KeyUseFactory';
import { KeyType } from './KeyTypeFactory';
import IKeyContainer, { CryptographicKey } from './IKeyContainer';

/**
 * Represents a Key container in JWK format.
 * A key container will hold different versions of JWK keys.
 * Each key in the key container is the same type and usage
 */
export default class KeyContainer implements IKeyContainer {
   /**
    * Create instance of @class KeyContainer
    */
  constructor (key: CryptographicKey) {
    this.keys = [key];
  }

   /**
    * Return all keys in the container
    */
  public keys: CryptographicKey[];

  /**
   * Key type
   */
  public get kty (): KeyType {
    return this.keys[0].kty;
  }

  /**
   * Intended use
   */
  public get use (): KeyUse | undefined {
    return this.keys[0].use;
  }

  /**
   * Algorithm intended for use with this key
   */
  public get alg (): string | undefined {
    return this.keys[0].alg;
  }

  /**
   * Algorithm intended for use with this key
   */
  public add (key: CryptographicKey): void {
    // Check for valid key to add
    if (this.keys.length !== 0 && key.kty !== this.kty) {
      throw new Error(`Cannot add a key with kty '${key.kty}' to a key container with kty '${this.kty}'`);
    }

    if (this.keys.length !== 0 && key.use !== this.use) {
      throw new Error(`Cannot add a key with use '${key.use}' to a key container with use '${this.use}'`);
    }

    this.keys.push(key);
  }

   /**
    * Get the default key from the key container
    */
  public getKey<T= CryptographicKey> (): T {
     // return last keys as reference
    return (this.keys as any)[this.keys.length - 1];
  }
  
  /**
   * True if private key is a remote key
   */
  public remotekey (): boolean {
    if (this.keys[0] && this.keys[0].kid) {
      return this.keys.length !== 0 &&  this.keys[0].kid.startsWith('https://');
    }

    return false;
  }

}
