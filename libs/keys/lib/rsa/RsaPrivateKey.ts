/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import RsaPublicKey from './RsaPublicKey';
import PrivateKey from '../PrivateKey';
import PublicKey from '../PublicKey';
import base64url from 'base64url';
const clone = require('clone');

/**
 * Represents an Elliptic Curve private key
 * @class
 * @extends PrivateKey
 */
export default class RsaPrivateKey extends RsaPublicKey implements PrivateKey {

  /**
   * Private exponent
   */
  public d: string;
  /**
   * Prime p
   */
  public p: string;
  /**
   * Prime q
   */
  public q: string;
  /**
   * Private dp
   */
  public dp: string;
  /**
   * Private dq
   */
  public dq: string;
  /**
   * Private qi
   */
  public qi: string;

  /**
   * Create instance of @class RsaPrivateKey
   */
  constructor (key: any) {
    super(key);
    this.d = typeof key.d === 'string' ?  key.d : base64url.encode(key.d);
    this.p = typeof key.p === 'string' ?  key.p : base64url.encode(key.p);
    this.q = typeof key.q === 'string' ?  key.q : base64url.encode(key.q);
    this.dp = typeof key.dp === 'string' ?  key.dp : base64url.encode(key.dp);
    this.dq = typeof key.dq === 'string' ?  key.dq : base64url.encode(key.dq);
    this.qi = typeof key.qi === 'string' ?  key.qi : base64url.encode(key.qi);
  }

  /**
   * Gets the corresponding public key
   * @returns The corresponding {@link PublicKey}
   */
  public getPublicKey (): PublicKey {
    const publicKey = clone(this);
    delete publicKey.d;
    delete publicKey.p;
    delete publicKey.q;
    delete publicKey.dp;
    delete publicKey.dq;
    delete publicKey.qi;
    return publicKey;
  }
}
