/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { ProtectionFormat } from 'verifiablecredentials-crypto-sdk-typescript-protocol-jose/lib';
import { Crypto, Jose } from './index';

/**
 * Builder class for the JOSE protocol
 */
export default class JoseBuilder {
  constructor(private _crypto: Crypto) {
  }

  private _protectedHeader: object = {};
  private _unprotectedHeader: object = {};
  private _serializationFormat: string = ProtectionFormat.JwsCompactJson;
  private _jwtProtocol: object | undefined;

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
    return this.jwtProtocol ? 'JWT' : 'JOSE';
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
  public useJwtProtocol(jwtProtocol: object): JoseBuilder {
    this._jwtProtocol = jwtProtocol;
    return this;
  }


  /**
    * Gets the JWT protocol. 
    * @returns The JWT protocol. 
    */
  public get jwtProtocol(): object | undefined {
    return this._jwtProtocol;
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

}