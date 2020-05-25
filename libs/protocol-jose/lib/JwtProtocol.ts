/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { PublicKey } from 'verifiablecredentials-crypto-sdk-typescript-keys';
import { ProtectionFormat, KeyReferenceOptions } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import { IVerificationResult, ICryptoToken, IPayloadProtectionOptions } from 'verifiablecredentials-crypto-sdk-typescript-protocols-common';
import JwsToken from './jws/JwsToken';
import { IJwsSigningOptions, IJwtSigningOptions } from './IJoseOptions';
import JwtToken from './jwt/JwtToken';

/**
 * Class to implement the Jwt protocol.
 */
export default class JwtProtocol {

  /**
   * Signs contents using the given private key reference.
   *
   * @param signingKeyReference Reference to the signing key.
   * @param payload to sign.
   * @param format of the final signature.
   * @param options used for the signature. These options override the options provided in the constructor.
   * @returns Signed payload in requested format.
   */
   public async sign (signingKeyReference: string | KeyReferenceOptions, payload: object, options: IPayloadProtectionOptions): Promise<ICryptoToken> {
    const jwtOptions: IJwtSigningOptions = JwsToken.fromPayloadProtectionOptions(options);
    const token: JwtToken = new JwtToken(jwtOptions);
    return JwsToken.toCryptoToken(ProtectionFormat.JwsCompactJson, await token.sign(signingKeyReference, payload), options);
   }

  /**
   * Verify the signature.
   *
   * @param validationKeys Public key to validate the signature.
   * @param payload that was signed
   * @param signature on payload  
   * @param options used for the signature. These options override the options provided in the constructor.
   * @returns True if signature validated.
   */
   public async verify (validationKeys: PublicKey[], _payload: Buffer, signature: ICryptoToken, options?: IPayloadProtectionOptions): Promise<IVerificationResult> {
    const jwsOptions: IJwsSigningOptions = JwsToken.fromPayloadProtectionOptions(<IPayloadProtectionOptions>options);
    const token: JwsToken = JwsToken.fromCryptoToken(signature, <IPayloadProtectionOptions>options);
    const result = await token.verify(validationKeys);
    return {
      result: result,
      reason: '',
      statusCode: 0,
      payload: null,
      alg: '',
    };
   }
}
