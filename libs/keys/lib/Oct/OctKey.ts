/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { KeyType } from '../KeyTypeFactory';
import JsonWebKey from '../JsonWebKey';
import SecretKey from '../SecretKey';

 /**
  * Represents an OCT key
  * @class
  * @extends JsonWebKey
  */
export default class OctKey extends JsonWebKey implements SecretKey {
   /**
    * secret
    */
  public k: string;

   /**
    * Set the Oct key type
    */
  kty = KeyType.Oct;

   /**
    * Create instance of @class EcPublicKey
    */
  constructor (key: string) {
    super({ kty: KeyType.Oct });
    this.k = key;
  }
}
