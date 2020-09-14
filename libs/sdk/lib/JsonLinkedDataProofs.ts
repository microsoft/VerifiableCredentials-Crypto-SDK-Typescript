/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { Crypto, ProtectionFormat, JoseBuilder } from './index';
import { IPayloadProtectionSigning } from 'verifiablecredentials-crypto-sdk-typescript-protocols-common';
const jsonld = require('jsonld');

export default class JsonLinkedDataProofs {

  /**
   * Create instance of <see @class Jose>
   * @param builder The builder object
   */
  constructor(
    private _signer: IPayloadProtectionSigning) {
  }

  /**
   * Embed the signature into the payload
   * @param payload to embed signature
   */
  public async sign(payload: object): Promise<object> {

    if (!payload) {
      throw new Error('JSON LD proofs input is undefined');
    }

    if (typeof payload !== 'object') {
      throw new Error('JSON LD proofs input should be an object');
    }
    const crypto = this._signer.builder.crypto;
    const [verifyData, proof] = await this.createVerifyData(payload, crypto);

    // sign payload
    let jwsSigner: IPayloadProtectionSigning = new JoseBuilder(this._signer.builder.crypto)
      .build();
      
    jwsSigner = await jwsSigner.sign(verifyData);
    proof.jws = jwsSigner.serialize();

    // Add proof
    (<any>payload).proof = proof;
    return payload;
  }

  public async createVerifyData(payload: any, crypto: Crypto, verificationMethod?: string, proofPurpose: string = 'assertionMethod'): Promise<[Buffer, any]> {
    verificationMethod = verificationMethod || `${crypto.builder.did}#${crypto.builder.signingKeyReference}`;

    const type = 'Ed25519Signature2018';  // needs to be calculated and put in a seperate suite
    const created = new Date().toUTCString();
    const proof: any = {
      '\@context': 'https://w3id.org/security/v2',
      type,
      verificationMethod,
      proofPurpose,
      created
    };
    const proofCanonized = await jsonld.canonize(proof, {
      algorithm: 'URDNA2015',
      format: 'application/n-quads'
    });
    const payloadCanonized = await jsonld.canonize(payload, {
      algorithm: 'URDNA2015',
      format: 'application/n-quads'
    });

    let proofHash = new Uint8Array(await crypto.builder.subtle.digest(
      {
        name: "SHA-256",
      },
      new Uint8Array(Buffer.from(proofCanonized))));
    let payloadHash = new Uint8Array(await crypto.builder.subtle.digest(
      {
        name: "SHA-256",
      },
    new Uint8Array(Buffer.from(payloadCanonized))));
    
    const buffers = [proofHash, payloadHash];
    const result = Buffer.concat(buffers);
    delete proof['\@context'];
    return [result, proof];
  }
}