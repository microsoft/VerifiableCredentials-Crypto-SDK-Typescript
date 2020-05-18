/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { KeyType } from '../KeyTypeFactory';
import JsonWebKey from '../JsonWebKey';
import base64url from 'base64url';

/**
 * Represents an RSA public key
 * @class
 * @extends PublicKey
 */
export default class RsaPublicKey extends JsonWebKey {
  /**
   * Public exponent
   */
  public e: string;
  /**
   * Modulus
   */
  public n: string;
  /**
   * Set the EC key type
   */
  kty = KeyType.RSA;
  /**
   * Set the default algorithm
   */
  alg = 'RS256';

  /**
   * Create instance of @class RsaPublicKey
   */
  constructor (key: any) {
    super(key);
    this.alg = key.alg;
    this.key_ops = key.key_ops;
    this.kid = key.kid;
    this.use = key.use;
    this.e = typeof key.e === 'string' ?  key.e : base64url.encode(key.e);
    this.n = typeof key.n === 'string' ?  key.n : base64url.encode(key.n);
  }
}
