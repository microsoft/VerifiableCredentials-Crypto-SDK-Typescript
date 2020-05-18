/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { KeyType } from '../KeyTypeFactory';
import JsonWebKey from '../JsonWebKey';
import PublicKey from '../PublicKey';
import base64url from 'base64url';

/**
 * Represents an Elliptic Curve public key
 * @class
 * @extends PublicKey
 */
export default class EcPublicKey extends JsonWebKey implements PublicKey {
  /**
   * curve
   */
  public crv: string | undefined;
  /**
   * x co-ordinate
   */
  public x: string;
  /**
   * y co-ordinate
   */
  public y: string;
  
  /**
   * Create instance of @class EcPublicKey
   */
  constructor (key: EcPublicKey) {
    super(key);
    this.crv = key.crv;
    this.x = typeof key.x === 'string' ?  key.x : base64url.encode(key.x);
    if (key.y) {
      // No y for OPK
      this.y = typeof key.y === 'string' ?  key.y : base64url.encode(key.y);
      this.kty = KeyType.EC;
    } else {
      this.y = <any>undefined;
      this.kty = KeyType.OKP;
    }
  }
}
