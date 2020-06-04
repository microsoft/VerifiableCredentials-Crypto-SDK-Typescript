/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { JoseBuilder, IJwsSigningOptions, JwsToken, ProtectionFormat } from './index';
import { ICryptoToken } from 'verifiablecredentials-crypto-sdk-typescript-protocols-common';

export default class Jose {

    /**
     * Create instance of <see @class Jose>
     * @param _builder The builder object
     */
  constructor(
    private _builder: JoseBuilder) {
    }
    
  /**
   * Signs contents using the given private key reference.
   *
   * @param signingKeyReference Reference to the signing key.
   * @param payload to sign.
   * @param format of the final signature.
   * @param options used for the signature. These options override the options provided in the constructor.
   * @returns Signed payload in requested format.
   */
  public async sign (payload: Buffer | object): Promise<ICryptoToken> {
    const jwsOptions: IJwsSigningOptions = JwsToken.frombuilder(this._builder);
    const token: JwsToken = new JwsToken(jwsOptions);
    const protectionFormat: ProtectionFormat = this.getProtectionFormat(this._builder.serializationFormat);
    return JwsToken.toCryptoToken(protectionFormat, await token.sign(this._builder.crypto.signingKeyReference, payload, protectionFormat), options);
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

   /**
   * Serialize a cryptographic token
   * @param token The crypto token to serialize.
   * @param format Specify the serialization format. If not specified, use default format.
   * @param options used for the decryption. These options override the options provided in the constructor.
   */
   public serialize (token: ICryptoToken, format: string, options: IPayloadProtectionOptions): string {
    const protocolFormat: ProtectionFormat = this.getProtectionFormat(format);
    
    switch (protocolFormat) {
      case ProtectionFormat.JwsFlatJson:
      case ProtectionFormat.JwsCompactJson:
      case ProtectionFormat.JwsGeneralJson:
        const signature: JwsToken = JwsToken.fromCryptoToken(token, options);
        return signature.serialize(protocolFormat);
      case ProtectionFormat.JweFlatJson:
      case ProtectionFormat.JweCompactJson:
      case ProtectionFormat.JweGeneralJson:
        const cipher: JweToken = JweToken.fromCryptoToken(token, options);
        return cipher.serialize(protocolFormat);
    default:
        throw new CryptoProtocolError(JoseConstants.Jose, `Serialization format '${format}' is not supported`);
    }
   }

  /**
   * Deserialize a cryptographic token
   * @param token The crypto token to deserialize.
   * @param format Specify the serialization format. If not specified, use default format.
   * @param options used for the decryption. These options override the options provided in the constructor.
   */
   public deserialize (token: string, format: string, options: IPayloadProtectionOptions): ICryptoToken {
    const protocolFormat: ProtectionFormat = this.getProtectionFormat(format);
    switch (protocolFormat) {
      case ProtectionFormat.JwsFlatJson:
      case ProtectionFormat.JwsCompactJson:
      case ProtectionFormat.JwsGeneralJson:
        const jwsProtectOptions = JwsToken.fromPayloadProtectionOptions(options);
        return JwsToken.toCryptoToken(protocolFormat, JwsToken.deserialize(token, jwsProtectOptions), options);
      case ProtectionFormat.JweFlatJson:
      case ProtectionFormat.JweCompactJson:
      case ProtectionFormat.JweGeneralJson:
        const jweProtectOptions = JweToken.fromPayloadProtectionOptions(options);
        return JweToken.toCryptoToken(protocolFormat, JweToken.deserialize(token, jweProtectOptions), options);
      default:
        throw new CryptoProtocolError(JoseConstants.Jose, `Serialization format '${format}' is not supported`);
    }
   }

  /**
   * Deserialize a cryptographic token
   * @param token The crypto token to deserialize.
   * @param options used for the token. These options override the options provided in the constructor.
   */
   public static deserialize (token: string, options?: IPayloadProtectionOptions): ICryptoToken {
    const parts = token.split('.');
    const protocol = new JoseProtocol();

    if (parts.length === 3) {
      const deserializationOptions = options ? JwsToken.fromPayloadProtectionOptions(options) : <IJwsSigningOptions>{};
      return JwsToken.toCryptoToken(ProtectionFormat.JwsCompactJson, JwsToken.deserialize(token, deserializationOptions), <IPayloadProtectionOptions>options);
    } else if (parts.length === 5) {
      const deserializationOptions = options ? JweToken.fromPayloadProtectionOptions(options) : <IJweEncryptionOptions>{};
      return JweToken.toCryptoToken(ProtectionFormat.JweCompactJson, JweToken.deserialize(token, deserializationOptions), <IPayloadProtectionOptions>options);
    }
    const parsed = JSON.parse(token);
    if (parsed[JoseConstants.tokenSignatures] || parsed[JoseConstants.tokenSignature]) {
      const deserializationOptions = options ? JwsToken.fromPayloadProtectionOptions(options) : <IJwsSigningOptions>{};
      return JwsToken.toCryptoToken(parsed[JoseConstants.tokenSignatures] ? ProtectionFormat.JwsGeneralJson : ProtectionFormat.JwsFlatJson, JwsToken.deserialize(token, deserializationOptions), <IPayloadProtectionOptions>options);
    }
    if (parsed[JoseConstants.tokenRecipients] || parsed[JoseConstants.tokenCiphertext]) {
      const deserializationOptions = options ? JweToken.fromPayloadProtectionOptions(options) : <IJweEncryptionOptions>{};
      return JweToken.toCryptoToken(parsed[JoseConstants.tokenRecipients] ? ProtectionFormat.JweGeneralJson : ProtectionFormat.JweFlatJson, JweToken.deserialize(token, deserializationOptions), <IPayloadProtectionOptions>options);
    }

    throw new CryptoProtocolError(JoseConstants.Jose, 'Unrecognised token to deserialize');
   }

   // Map string to protection format
  public getProtectionFormat(format: string): ProtectionFormat {
    switch(format.toLocaleLowerCase()) {
      case 'jwsflatjson': return ProtectionFormat.JwsFlatJson;
      case 'jwscompactjson': return ProtectionFormat.JwsCompactJson;
      case 'jwsgeneraljson': return ProtectionFormat.JwsGeneralJson;
      case 'jweflatjson': return ProtectionFormat.JweFlatJson;
      case 'jwecompactjson': return ProtectionFormat.JweCompactJson;
      case 'jwegeneraljson': return ProtectionFormat.JweGeneralJson;
      default:
        throw new CryptoProtocolError(JoseConstants.Jose, `Format '${format}' is not supported`);
    }
  }

}