/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { IJwsSigningOptions, JwsToken, ProtectionFormat } from 'verifiablecredentials-crypto-sdk-typescript-protocol-jose/lib';
import { IPayloadProtectionSigning, CryptoProtocolError, IProtocolCryptoToken } from 'verifiablecredentials-crypto-sdk-typescript-protocols-common';
import { PublicKey, JoseConstants } from 'verifiablecredentials-crypto-sdk-typescript-keys';
import { JoseBuilder } from './index';
import { JoseToken } from 'verifiablecredentials-crypto-sdk-typescript-protocol-jose';

export default class Jose implements IPayloadProtectionSigning {

  /**
   * Create instance of <see @class Jose>
   * @param builder The builder object
   */
  constructor(
    public builder: JoseBuilder) {
  }

  private _token: JwsToken | undefined;
  /**
   * Signs contents using the given private key reference.
   *
   * @param signingKeyReference Reference to the signing key.
   * @param payload to sign.
   * @param format of the final signature.
   * @param options used for the signature. These options override the options provided in the constructor.
   * @returns Signed payload in requested format.
   */
  public async sign(payload: Buffer | object): Promise<IPayloadProtectionSigning> {
    const jwsOptions: IJwsSigningOptions = Jose.optionsFromBuilder(this.builder);
    const token: JwsToken = new JwsToken(jwsOptions);
    const protectionFormat = this.getProtectionFormat(this.builder.serializationFormat);

    this._token = await token.sign(this.builder.crypto.builder.signingKeyReference!, <Buffer>payload, protectionFormat);
    return this;
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
  public async verify(validationKeys: PublicKey[]): Promise<boolean> {
    const jwsOptions: IJwsSigningOptions = Jose.optionsFromBuilder(this.builder);
    if (!this._token) {
      return Promise.reject('Import a token by deserialize');
    }

    const result = await this._token.verify(validationKeys, jwsOptions);
    return result;
  }

  /**
  * Serialize a cryptographic token
  * @param token The crypto token to serialize.
  * @param format Specify the serialization format. If not specified, use default format.
  * @param options used for the decryption. These options override the options provided in the constructor.
  */
  public serialize(): string {
    const protocolFormat: ProtectionFormat = this.getProtectionFormat(this.builder.serializationFormat);
    if (!this._token) {
      throw new CryptoProtocolError(JoseConstants.Jose, `No token to serialize.`);
    }

    switch (protocolFormat) {
      case ProtectionFormat.JwsFlatJson:
      case ProtectionFormat.JwsCompactJson:
      case ProtectionFormat.JwsGeneralJson:
        return this._token.serialize(protocolFormat);
      default:
        throw new CryptoProtocolError(JoseConstants.Jose, `Serialization format '${this.builder.serializationFormat}' is not supported`);
    }
  }

  /**
   * Deserialize a cryptographic token
   * @param token The crypto token to deserialize.
   * @param format Specify the serialization format. If not specified, use default format.
   * @param options used for the decryption. These options override the options provided in the constructor.
   */
  public deserialize(token: string): IPayloadProtectionSigning {
    const protocolFormat: ProtectionFormat = this.getProtectionFormat(this.builder.serializationFormat);
    const jwsOptions: IJwsSigningOptions = Jose.optionsFromBuilder(this.builder);

    switch (protocolFormat) {
      case ProtectionFormat.JwsFlatJson:
      case ProtectionFormat.JwsCompactJson:
      case ProtectionFormat.JwsGeneralJson:
        const jwsProtectOptions = Jose.optionsFromBuilder(this.builder);
        this._token = JwsToken.deserialize(token, jwsProtectOptions);
        return this;
      default:
        throw new CryptoProtocolError(JoseConstants.Jose, `Serialization format '${this.builder.serializationFormat}' is not supported`);
    }
  }

  /**
   * Deserialize a cryptographic token
   * @param token The crypto token to deserialize.
   * @param options used for the token. These options override the options provided in the constructor.
   */
  /*
  public static deserialize(token: string, options?: IPayloadProtectionOptions): ICryptoToken {
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
*/

  // Map string to protection format
  public getProtectionFormat(format: string): ProtectionFormat {
    switch (format.toLocaleLowerCase()) {
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

  /**
   * Convert a @class IPayloadProtectionOptions into a @class IJwsSigningOptions
   * @param protectOptions to convert
   */
  public static optionsFromBuilder(builder: JoseBuilder): IJwsSigningOptions {
    return <IJwsSigningOptions> {
      cryptoFactory: builder.crypto.builder.cryptoFactory,
      protectedHeader: builder.protectedHeader, 
      unprotectedHeader: builder.unprotectedHeader
    };
  }

}