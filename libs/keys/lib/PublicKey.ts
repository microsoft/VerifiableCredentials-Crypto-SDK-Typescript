/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import base64url from 'base64url';
import JsonWebKey from './JsonWebKey';
const jose = require('node-jose');

/**
 * JWK key operations
 */
export enum KeyOperation {
  Sign = 'sign',
  Verify = 'verify',
  Encrypt = 'encrypt',
  Decrypt = 'decrypt',
  WrapKey = 'wrapKey',
  UnwrapKey = 'unwrapKey',
  DeriveKey = 'deriveKey',
  DeriveBits = 'deriveBits'
}

/**
 * Represents a Public Key in JWK format.
 * @class
 * @abstract
 * @hideconstructor
 */
export default abstract class PublicKey extends JsonWebKey {
  /**
   * Obtains the thumbprint for the jwk parameter
   * @param jwk JSON object representation of a JWK
   */
  static async getThumbprint (publicKey: PublicKey): Promise<string> {
    const key = await jose.JWK.asKey(publicKey);
    const thumbprint = await key.thumbprint('SHA-256');
    return base64url.encode(thumbprint);
  }
}
