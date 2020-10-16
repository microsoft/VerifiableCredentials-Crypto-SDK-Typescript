/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { IJwsSigningOptions, JwsToken } from 'verifiablecredentials-crypto-sdk-typescript-protocol-jose';
import { IPayloadProtectionSigning, CryptoProtocolError } from 'verifiablecredentials-crypto-sdk-typescript-protocols-common';
import { PublicKey, JoseConstants } from 'verifiablecredentials-crypto-sdk-typescript-keys';
import { IJsonLinkedDataProofSuite, JoseBuilder, KeyStoreOptions, ProtectionFormat } from './index';
import { TSMap } from 'typescript-map';
import { v4 as uuidv4 } from 'uuid';

export default class Jose implements IPayloadProtectionSigning {

  /**
   * Create instance of <see @class Jose>
   * @param builder The builder object
   */
  constructor(
    public builder: JoseBuilder) {
  }

  private _jsonLdProof: object | undefined;
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

    if (this.builder.isJsonLdProofsProtocol()) {
      // Support json ld proofs
      console.log('Support JSON LD proofs');
      if (typeof payload === 'string' || payload instanceof Buffer) {
        return Promise.reject(`Input to sign JSON LD must be an object`);
      }

      let suite: IJsonLinkedDataProofSuite;
      try {
        suite = this.builder.getLinkedDataProofSuite(this);
      } catch (exception) {
        return Promise.reject(exception.message);
      }

      this._jsonLdProof = await suite.sign(payload);
      console.log(`JSON LD Proof: ${this._jsonLdProof}`);
      return this;
    } 

    if (this.isJwtProtocol()) {
      if (typeof payload === 'string' || payload instanceof Buffer) {
        return Promise.reject(`Input to sign JWT must be an object`);
      }

      // Add standardized properties
      const current = Math.trunc(Date.now() / 1000);
      if (!(<any>payload).nbf) {
        (<any>payload).nbf = this.builder.jwtProtocol!.nbf || current;
      }
      if (!(<any>payload).exp) {
        (<any>payload).exp = this.builder.jwtProtocol!.exp || current + (60 * 60);
      }

      if (!(<any>payload).jti) {
        (<any>payload).jti = this.builder.jwtProtocol!.jti || uuidv4();
      }

      // Override properties
      for (let key in this.builder.jwtProtocol) {
        if (key in ['nbf', 'exp', 'jti']) {
          continue;
        }
        (<any>payload)[key] = (<any>payload)[key] || this.builder.jwtProtocol[key];
      }
    }

    payload = Buffer.from(JSON.stringify(payload));
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
    if (!validationKeys) {
      const validationKeyContainer = await this.builder.crypto.builder.keyStore.get(this.builder.crypto.builder.signingKeyReference!, new KeyStoreOptions({ publicKeyOnly: true }));
      validationKeys = [validationKeyContainer.getKey<PublicKey>()]
    }

    if (this.builder.isJsonLdProofsProtocol()) {
      // Support json ld proofs

      if (!this._jsonLdProof) {
        return Promise.reject('Import a credential by deserialize');
      }

      let suite: IJsonLinkedDataProofSuite;
      try {
        suite = this.builder.getLinkedDataProofSuite(this);
      } catch (exception) {
        return Promise.reject(exception.message);
      }
      return await suite.verify(validationKeys, this._jsonLdProof);
    }

    const jwsOptions: IJwsSigningOptions = Jose.optionsFromBuilder(this.builder);
    if (!this._token) {
      return Promise.reject('Import a token by deserialize');
    }

    const result = await this._token.verify(validationKeys!, jwsOptions);
    return result;
  }

  /**
  * Serialize a cryptographic token
  */
  public async serialize(): Promise<string> {
    const protocolFormat: ProtectionFormat = Jose.getProtectionFormat(this.builder.serializationFormat);
    if (!this._token) {
      return Promise.reject(`No token to serialize`);
    }

    if (this.builder.isJsonLdProofsProtocol()) {
      if (this._jsonLdProof) {

        let suite: IJsonLinkedDataProofSuite;
        suite = this.builder.getLinkedDataProofSuite(this);
        return suite.serialize(this._jsonLdProof);
      }

      return Promise.reject(`No token to serialize`);
    }

    switch (protocolFormat) {
      case ProtectionFormat.JwsFlatJson:
      case ProtectionFormat.JwsCompactJson:
      case ProtectionFormat.JwsGeneralJson:
        return Promise.resolve(this._token.serialize(protocolFormat)); ``
      default:
        return Promise.reject(`Serialization format '${this.builder.serializationFormat}' is not supported`);
    }
  }

  /**
   * Deserialize a cryptographic token
   * @param token The crypto token to deserialize.
   */
  public async deserialize(token: string): Promise<IPayloadProtectionSigning> {

    if (this.builder.isJsonLdProofsProtocol()) {
      let suite: IJsonLinkedDataProofSuite;
      try {
        suite = this.builder.getLinkedDataProofSuite(this);
        this._jsonLdProof = await suite.deserialize(token);
        return Promise.resolve(this);
      } catch (exception) {
        return Promise.reject(exception.message);
      }
    }

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
        this._signaturePayload = this._token.payload;
        return Promise.resolve(this);
      default:
        return Promise.reject(`Serialization format '${this.builder.serializationFormat}' is not supported`);
    }
  }

  /**
   * True if JSON LD proof protocol is selected
   */
  private isJwtProtocol(): boolean {
    return this.builder.jwtProtocol !== undefined;
  }

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