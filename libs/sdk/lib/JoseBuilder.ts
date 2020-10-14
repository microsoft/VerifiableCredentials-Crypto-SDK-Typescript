import { IPayloadProtectionSigning } from 'verifiablecredentials-crypto-sdk-typescript-protocols-common';
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
  private _linkedDataProofsProtocol: ({ [suite: string]: () => IJsonLinkedDataProofSuite }) | undefined;
  private _jsonLdProofSuite: string | undefined;
  private _kid: string | undefined;

  /**
   * Set the default linked data proof suites
   */
  public linkedDataProofSuites: { [suite: string]: () => IJsonLinkedDataProofSuite } = {
    JcsEd25519Signature2020: () => new SuiteJcsEd25519Signature2020(this.build())
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
    if (this.linkedDataProofsProtocol) {
      return JoseBuilder.JSONLDProofs;
    } else if (this.jwtProtocol) {
      return JoseBuilder.JWT;
    }

    return JoseBuilder.JOSE;
  }

  /**
   * Gets the default suite based on _jsonLdProofSuite
   */
  public getLinkedDataProofSuite(): IJsonLinkedDataProofSuite {
    if (!this._jsonLdProofSuite) {
      throw new Error(`No suite defined. Use jsonBuilder.uselinkedDataProofsProtocol() to specify the suite to use.`);
    }

    let suite: (() => IJsonLinkedDataProofSuite) | undefined = this.linkedDataProofSuites[this._jsonLdProofSuite];
    if (!suite) {
      // Check if new suites are passed in
      suite = this._linkedDataProofsProtocol ? this._linkedDataProofsProtocol[this._jsonLdProofSuite] : undefined;
    }

    if (!suite) {
      throw new Error(`Suite ${this._jsonLdProofSuite} does not exist. Use jsonBuilder.uselinkedDataProofsProtocol() to specify the suite to use.`);
    }

    return suite();
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
    * @param linkedDataProofsProtocol Define properties that need to be added to the body for the JSON-LD format
    * @returns The jose builder
    */
  public uselinkedDataProofsProtocol(suite: string, linkedDataProofsProtocol: { [suite: string]: any } = {}): JoseBuilder {
    this._linkedDataProofsProtocol = linkedDataProofsProtocol;
    this._jsonLdProofSuite = suite;

    // check for valid suite
    this.getLinkedDataProofSuite();
    return this;
  }

  /**
    * Gets the JSON linked data proofs protocol. 
    * @returns The JWT protocol. 
    */
   public get linkedDataProofsProtocol(): { [key: string]: any } | undefined {
    return this._linkedDataProofsProtocol;
  }

  /**
    * True if the the JSON linked data proofs protocol is enabled. 
    */
  public isLinkedDataProofsProtocol(): boolean {
    return this._linkedDataProofsProtocol !== undefined;
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