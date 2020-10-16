import { IPayloadProtection, IPayloadProtectionSigning } from 'verifiablecredentials-crypto-sdk-typescript-protocols-common';
/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { Crypto, IJsonLinkedDataProofSuite, Jose, ProtectionFormat } from './index';
import SuiteJcsEd25519Signature2020 from './suites/SuiteJcsEd25519Signature2020';

/**
 * Builder class for the JOSE protocol
 */
export default class JoseBuilder {
  public static JSONLDProofs = 'JSONLDProofs';
  public static JWT = 'JWT';
  public static JOSE = 'JOSE';

  /**
   * Create an instance of the JoseBuilder
   * @param _crypto The crypto object
   */
  constructor(private _crypto: Crypto) {
  }

  private _protectedHeader: object = { typ: 'JWT' };
  private _unprotectedHeader: object = {};
  private _serializationFormat: string = ProtectionFormat.JwsCompactJson;
  private _jwtProtocol: { [key: string]: any } | undefined;
  private _jsonLdProofsProtocol: ({ [suite: string]: (signatureProtocol: IPayloadProtectionSigning) => IJsonLinkedDataProofSuite }) | undefined;
  private _jsonLdProofSuite: string | undefined;
  private _kid: string | undefined;

  /**
   * Set the default linked data proof suites
   */
  public linkedDataProofSuites: { [suite: string]: (signatureProtocol: IPayloadProtectionSigning) => IJsonLinkedDataProofSuite } = {
    JcsEd25519Signature2020: (signatureProtocol: IPayloadProtectionSigning): IJsonLinkedDataProofSuite => new SuiteJcsEd25519Signature2020(signatureProtocol)
  }

  /**
   * Gets the crypto object
   */
  public get crypto() {
    return this._crypto;
  }

  /**
   * Gets the protocol name
   */
  public get protocol() {
    if (this.jsonLdProofsProtocol) {
      return JoseBuilder.JSONLDProofs;
    } else if (this.jwtProtocol) {
      return JoseBuilder.JWT;
    }

    return JoseBuilder.JOSE;
  }

  /**
   * Build the jose object
   */
  public build(): Jose {
    return new Jose(this);
  }

  /**
    * Sets JWT protocol. 
    * @param jwtProtocol Define properties that need to be added to the body for the JWT format
    * @returns The jose builder
    */
  public useJwtProtocol(jwtProtocol: { [key: string]: any } = {}): JoseBuilder {
    this._jwtProtocol = jwtProtocol;
    return this;
  }


  /**
    * Gets the JWT protocol. 
    * @returns The JWT protocol. 
    */
  public get jwtProtocol(): { [key: string]: any } | undefined {
    return this._jwtProtocol;
  }

  /**
    * Sets JSON linked data proofs protocol. 
    * @suite Name of the suite
    * @param jsonLdProofsProtocol API implementing the suite
    * @returns The jose builder
    */
  public useJsonLdProofsProtocol(suite: string, jsonLdProofsProtocol: (signatureProtocol: IPayloadProtectionSigning) => IJsonLinkedDataProofSuite): JoseBuilder {
    if (!this._jsonLdProofsProtocol) {
      this._jsonLdProofsProtocol = {};
    }
    this._jsonLdProofsProtocol[suite] = jsonLdProofsProtocol

    this._jsonLdProofSuite = suite;

    // check for valid suite
    this.getLinkedDataProofSuite(this.build());
    return this;
  }

  /**
   * Gets the default suite based on _jsonLdProofSuite
   * @params signatureProtocol The underlying protocol API
   */
  public getLinkedDataProofSuite(signatureProtocol: IPayloadProtectionSigning): IJsonLinkedDataProofSuite {
    if (!this._jsonLdProofSuite) {
      throw new Error(`No suite defined. Use jsonBuilder..useJsonLdProofsProtocol() to specify the suite to use.`);
    }

    let suite: (signatureProtocol: IPayloadProtectionSigning) => IJsonLinkedDataProofSuite = this.linkedDataProofSuites[this._jsonLdProofSuite];
    if (!suite) {
      // Check if new suites are passed in
      if (this._jsonLdProofsProtocol) {
        suite = this._jsonLdProofsProtocol[this._jsonLdProofSuite];
      }
    }

    if (!suite) {
      throw new Error(`Suite '${this._jsonLdProofSuite}' does not exist. Use jsonBuilder..useJsonLdProofsProtocol() to specify the suite to use.`);
    }

    return suite(signatureProtocol);
  }

  /**
    * Gets the JSON linked data proofs protocol. 
    * @returns The JWT protocol. 
    */
   public get jsonLdProofsProtocol(): { [key: string]: any } | undefined {
    return this._jsonLdProofsProtocol;
  }

  /**
    * True if the the JSON linked data proofs protocol is enabled. 
    */
  public isJsonLdProofsProtocol(): boolean {
    return this._jsonLdProofsProtocol !== undefined;
  }

  /**
    * Sets the protected header. If the value is set, the protcol will not change it
    * @param protectedHeader Define properties that need to be added to the protected header
    * @returns The jose builder
    */
  public useProtectedHeader(protectedHeader: object): JoseBuilder {
    this._protectedHeader = protectedHeader;
    return this;
  }


  /**
    * Gets the protected header. 
    * @returns The protected header. 
    */
  public get protectedHeader(): object {
    return this._protectedHeader;
  }

  /**
    * Sets the unprotected header. If the value is set, the protcol will not change it
    * @param unprotectedHeader Define properties that need to be added to the unprotected header
    * @returns The jose builder
    */
  public useUnprotectedHeader(unprotectedHeader: object): JoseBuilder {
    this._unprotectedHeader = unprotectedHeader;
    return this;
  }

  /**
    * Gets the unprotected header. 
    * @returns The unprotected header. 
    */
  public get unprotectedHeader(): object {
    return this._unprotectedHeader;
  }


  /**
    * Sets the serialization format.
    * @param serializationFormat Define properties that need to be added to the unprotected header
    * @returns The jose builder
    */
  public useSerializationFormat(serializationFormat: string): JoseBuilder {
    this._serializationFormat = serializationFormat;
    return this;
  }

  /**
    * Gets the serialization format. 
    * @returns The serialization format.
    */
  public get serializationFormat(): string {
    return this._serializationFormat;
  }

  /**
    * Sets the kid in protected header.
    * @param kid Define kid for header
    * @returns The jose builder
    */
  public useKid(kid: string): JoseBuilder {
    this._kid = kid;
    return this;
  }

  /**
    * Gets the kid in protected header. 
    * @returns The serialization format.
    */
  public get kid(): string | undefined {
    return this._kid;
  }

}