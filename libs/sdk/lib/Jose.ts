/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { IJwsSigningOptions, JwsToken } from 'verifiablecredentials-crypto-sdk-typescript-protocol-jose';
import { IPayloadProtectionSigning, CryptoProtocolError, IProtocolCryptoToken } from 'verifiablecredentials-crypto-sdk-typescript-protocols-common';
import { PublicKey, JoseConstants } from 'verifiablecredentials-crypto-sdk-typescript-keys';
import { JoseBuilder, KeyStoreOptions, ProtectionFormat } from './index';
import { TSMap } from 'typescript-map';

export default class Jose implements IPayloadProtectionSigning {

  /**
   * Create instance of <see @class Jose>
   * @param builder The builder object
   */
  constructor(
    public builder: JoseBuilder) {
  }

  private _token: JwsToken | undefined;
  private _signatureProtectedHeader: any | undefined;
  private _signatureHeader: any | undefined;
  private _signaturePayload: Buffer | undefined;
  
  /**
   * Gets the protected header on the signature
   */
  public get signatureProtectedHeader() {
    return this._signatureProtectedHeader;
  }


  /**
   * Gets the header on the signature
   */
  public get signatureHeader() {
    return this._signatureHeader;
  }

  /**
   * Gets the payload for the signature
   */
  public get signaturePayload() {
    return this._signaturePayload;
  }


  /**
   * Signs contents using the given private key reference.
   *
   * @param payload to sign.
   * @returns Signed payload in requested format.
   */
  public async sign(payload: Buffer | object): Promise<IPayloadProtectionSigning> {
    const jwsOptions: IJwsSigningOptions = Jose.optionsFromBuilder(this.builder);

    // Set the protected header
    const kid = this.builder.kid || `${this.builder.crypto.builder.did}#${this.builder.crypto.builder.signingKeyReference.keyReference}`;
    jwsOptions.protected!.set('kid', kid);
    jwsOptions.protected!.set('typ', 'JWT');
    const token: JwsToken = new JwsToken(jwsOptions);
    const protectionFormat = Jose.getProtectionFormat(this.builder.serializationFormat);

    this._token = await token.sign(this.builder.crypto.builder.signingKeyReference, <Buffer>payload, protectionFormat);
    return this;
  }

  /**
   * Verify the signature.
   *
   * @param validationKeys Public key to validate the signature.
   * @returns True if signature validated.
   */
  public async verify(validationKeys?: PublicKey[]): Promise<boolean> {
    const jwsOptions: IJwsSigningOptions = Jose.optionsFromBuilder(this.builder);
    if (!this._token) {
      return Promise.reject('Import a token by deserialize');
    }

    if (!validationKeys) {
      const validationKeyContainer = await this.builder.crypto.builder.keyStore.get(this.builder.crypto.builder.signingKeyReference!, new KeyStoreOptions({ publicKeyOnly: true }));
      validationKeys = [validationKeyContainer.getKey<PublicKey>()]
    }

    const result = await this._token.verify(validationKeys!, jwsOptions);
    return result;
  }

  /**
  * Serialize a cryptographic token
  */
  public serialize(): string {
    const protocolFormat: ProtectionFormat = Jose.getProtectionFormat(this.builder.serializationFormat);
    if (!this._token) {
      throw new CryptoProtocolError(JoseConstants.Jose, `No token to serialize`);
    }

    switch (protocolFormat) {
      case ProtectionFormat.JwsFlatJson:
      case ProtectionFormat.JwsCompactJson:
      case ProtectionFormat.JwsGeneralJson:
        return this._token.serialize(protocolFormat); ``
      default:
        throw new CryptoProtocolError(JoseConstants.Jose, `Serialization format '${this.builder.serializationFormat}' is not supported`);
    }
  }

  /**
   * Deserialize a cryptographic token
   * @param token The crypto token to deserialize.
   */
  public deserialize(token: string): IPayloadProtectionSigning {
    const protocolFormat: ProtectionFormat = Jose.getProtectionFormat(this.builder.serializationFormat);
    const jwsOptions: IJwsSigningOptions = Jose.optionsFromBuilder(this.builder);

    switch (protocolFormat) {
      case ProtectionFormat.JwsFlatJson:
      case ProtectionFormat.JwsCompactJson:
      case ProtectionFormat.JwsGeneralJson:
        const jwsProtectOptions = Jose.optionsFromBuilder(this.builder);
        this._token = JwsToken.deserialize(token, jwsProtectOptions);

        // Get headers
        this._signatureProtectedHeader = {};
        this._signatureHeader = {};
        const protectedHeader = this._token.signatures[0].protected || new TSMap();
        const header = this._token.signatures[0].header || new TSMap();
        Object.keys(protectedHeader.keys()).forEach((index) => {
          const key = protectedHeader.keys()[parseInt(index)];
          this._signatureProtectedHeader[key] = protectedHeader.get(key)
        });
        Object.keys(header.keys()).forEach((index) => {
          const key = header.keys()[parseInt(index)];
          this._signatureHeader[key] = header.get(key)
        });

        // get payload
        this._signaturePayload =  this._token.payload;

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
  public static getProtectionFormat(format: string): ProtectionFormat {
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

    const protectedHeader = new TSMap();
    if (builder.protectedHeader) {
      const header: any = builder.protectedHeader;
      Object.keys(header).forEach(key => protectedHeader.set(key, header[key]));
    }

    const unprotectedHeader = new TSMap();
    if (builder.unprotectedHeader) {
      const header: any = builder.unprotectedHeader;
      Object.keys(header).forEach(key => unprotectedHeader.set(key, header[key]));
    }
    return <IJwsSigningOptions>{
      cryptoFactory: builder.crypto.builder.cryptoFactory,
      protected: protectedHeader,
      unprotected: unprotectedHeader
    };
  }

}