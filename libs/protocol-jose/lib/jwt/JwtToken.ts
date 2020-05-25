/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { PublicKey, JoseConstants } from 'verifiablecredentials-crypto-sdk-typescript-keys';
import { ProtectionFormat, KeyReferenceOptions } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import { TSMap } from 'typescript-map';
import { IJwtSigningOptions } from '../IJoseOptions';
import { JwsToken } from '../index';

/**
 * Default expiry time
 */
const EXPIRY_IN_SECONDS = 3600;

/**
 * Class for handling JWT token operations.
 */
export default class JwtToken {

  /**
   * Create an Jws token object
   * @param options Set of jws token options
   */
  constructor(public options?: IJwtSigningOptions) {
  }
  
  /**
   * Signs contents using the given private key in JWK format.
   *
   * @param signingKeyReference Reference to the signing key.
   * @param payload Set of claims to sign
   * @param options used for the signature. These options override the options provided in the constructor.
   * @returns Signed payload in compact JWT format.
   */
  public async sign(
    signingKeyReference: string | KeyReferenceOptions,
    payload: object,
    options?: IJwtSigningOptions
  ): Promise<JwsToken> {

    if (typeof payload !== 'object') {
      return Promise.reject(`JWT payload needs to be an object with a set of claims`);
    }

    options = options || this.options;
    if (!options) {
      return Promise.reject(`JWT need to be defined`);
    }

     // Set the protected header
     const protectedHeader = <TSMap<string, string>> (options.protected && options.protected.has(JoseConstants.optionProtectedHeader) ? options.protected.get(JoseConstants.optionProtectedHeader) : new TSMap<string, string>());

     //protectedHeader.set('kid', `${this._did}#${this._signingKeyReference}`);
     if (!protectedHeader.has('typ')) {
      protectedHeader.set('typ', 'JWT');
     } 

     options.protected = protectedHeader;

    payload = JwtToken.addJwtProps(payload, options)
    const token = new JwsToken(options);
    const payloadBuffer = Buffer.from(JSON.stringify(payload));
    return token.sign(signingKeyReference, payloadBuffer, ProtectionFormat.JwsCompactJson, options);
  }
 
  /**
   * Verify the JWS signature.
   * TODO validate standard props
   * @param validationKeys Public JWK key to validate the signature.
   * @param options used for the signature. These options override the options provided in the constructor.
   * @returns True if signature validated.
   */
  public async verify (validationKeys: PublicKey[], options?: IJwtSigningOptions): Promise<boolean> {
    const token = new JwsToken(options);
    return token.verify(validationKeys, options);
  }

  /**
   * Add specific JWT properties
   * @param payload Object to extend
   * @param options Signature options containing fields to add
   */
  private static addJwtProps(payload: any, options?: IJwtSigningOptions): object {
    const current = Math.trunc(Date.now() / 1000);
    const iat = current;
    let expiry = options && options.expiryInSeconds ? iat + options.expiryInSeconds : iat + EXPIRY_IN_SECONDS;

    if (!payload.iat) {
      payload.iat = iat;
    }

    if (!payload.exp) {
      payload.exp = expiry;
    }

    return payload; 
   }

}
