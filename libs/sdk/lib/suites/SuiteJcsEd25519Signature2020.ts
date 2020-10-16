/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import JsonLinkedDataProofsBase from '../JsonLinkedDataProofsBase';
import { CryptoHelpers, IJsonLinkedDataProofSuite, Crypto, SubtleCryptoExtension } from '../index';
import { IPayloadProtectionSigning } from 'verifiablecredentials-crypto-sdk-typescript-protocols-common';
import { PublicKey } from 'verifiablecredentials-crypto-sdk-typescript-keys';
import { v4 as uuid } from 'uuid';
import { CryptoAlgorithm } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
const clone = require('clone');
const json = require('canonicaljson');
const bs58 = require('bs58');

export default class SuiteJcsEd25519Signature2020 extends JsonLinkedDataProofsBase implements IJsonLinkedDataProofSuite {
  /**
   * Create instance of <see @class Jose>
   * @param builder The builder object
   */
  constructor(
    protected _signer: IPayloadProtectionSigning) {
    super(_signer);
  }

  /**
   * Gets the type of the suite
   */
  public get type(): string[] {
    return ['JcsEd25519Signature2020']
  }

  /**
   * Gets the algorithm for the suite
   */
  public get alg(): string{
    return 'EdDSA';
  }

  /**
   * Embed the signature into the payload
   * @param payload to embed signature
   */
  public async sign(payload: any): Promise<any> {

    if (!payload) {
      return Promise.reject('JSON LD proof input is undefined');
    }

    if (typeof payload !== 'object') {
      return Promise.reject('JSON LD proof input should be an object');
    }

    const crypto = this._signer.builder.crypto;
    const verifyData = await this.createVerifyData(payload, crypto);

    // sign payload
    const payloadToSign = verifyData;

    const alg = 'eddsa';
    const algorithm: CryptoAlgorithm = CryptoHelpers.jwaToWebCrypto(alg);
    const subtleExtension = new SubtleCryptoExtension(crypto.builder.cryptoFactory);
    const signature = await subtleExtension.signByKeyStore(algorithm, crypto.builder.signingKeyReference, payloadToSign);
    payload.proof.signatureValue = bs58.encode(signature);
    this._credential = payload;
    return this._credential;
  }

  /**
   * Verify the signature.
   *
   * @param validationKeys Public key to validate the signature.
    * @param signedPayload Optional. The payload to verify
    * @returns True if signature validated.
   */
  public async verify(validationKeys?: PublicKey[], signedPayload?: any): Promise<boolean> {
    this._credential = signedPayload ? signedPayload : this._credential;
    if (!this._credential) {
      return Promise.reject('Import a credential by deserialize');
    }


    // create payload
    const proof = this._credential.proof;

    if (!proof) {
      return Promise.reject('No proof to validate in signedPayload');
    }

    const payload = clone(this._credential);
    delete payload.proof.signatureValue;

    const crypto = this._signer.builder.crypto;
    const verifyData = await this.createVerifyData(payload, crypto, proof);

    const alg = 'eddsa';
    const algorithm: CryptoAlgorithm = CryptoHelpers.jwaToWebCrypto(alg);
    const subtleExtension = new SubtleCryptoExtension(crypto.builder.cryptoFactory);

    const signatureValue = proof.signatureValue;
    if (!signatureValue) {
      return Promise.reject('Proof does not contain the signatureValue');
    }

    const signature = bs58.decode(signatureValue);
    const result = await subtleExtension.verifyByJwk(algorithm, validationKeys![0], signature, verifyData);
    return result;
  }

  /**
  * Serialize a cryptographic token
  */
  public serialize(signedPayload?: any): Promise<string> {
    return super.serialize(signedPayload);
  }

  /**
   * Deserialize a credential
   * @param credential The credential to deserialize.
   */
  public deserialize(credential: string): Promise<any> {
    return super.deserialize(credential);
  }

  
  /**
   * Create the reference data used for verification and signatures
   */
  public async createVerifyData(payload: any, crypto: Crypto, proof?: any, verificationMethod?: string): Promise<Buffer> {
    verificationMethod = verificationMethod || `${crypto.builder.did}#${crypto.builder.signingKeyReference.keyReference}`;

    let embeddedProof: any;
    if (!proof) {
      const type = 'JcsEd25519Signature2020';  // needs to be calculated and put in a seperate suite
      const created = new Date().toUTCString();
      const nonce = uuid();
      embeddedProof = {
        type,
        nonce,
        verificationMethod,
        created
      };
    } else {
      embeddedProof = clone(proof);
      delete embeddedProof.signatureValue;
    }
    payload.proof = embeddedProof;
    const payloadCanonized = json.stringify(payload);
    return Buffer.from(payloadCanonized);
  }

}