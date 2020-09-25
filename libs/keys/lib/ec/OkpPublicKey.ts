/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { KeyType } from '../KeyTypeFactory';
import JsonWebKey from '../JsonWebKey';
import PublicKey from '../PublicKey';
import base64url from 'base64url';

/**
 * Represents an Elliptic Curve public key (Edward curve)
 * @class
 * @extends PublicKey
 */
export default class OkpPublicKey extends JsonWebKey implements PublicKey {
  /**
   * curve
   */
  public crv: string | undefined;

  /**
   * x co-ordinate
   */
  public x: string;

  /**
   * alg
   */
  public alg: string;
  
  /**
   * Create instance of @class EcPublicKey
   */
  constructor (key: OkpPublicKey) {
    super(key);
    this.crv = key.crv;
    this.x = typeof key.x === 'string' ?  key.x : base64url.encode(key.x);
    this.alg = key.alg;
    this.kty = KeyType.OKP;
  }
}
