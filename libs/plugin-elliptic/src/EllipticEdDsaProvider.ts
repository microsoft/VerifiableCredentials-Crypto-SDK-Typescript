/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import EllipticDsaProvider from './EllipticDsaProvider';
import { SubtleCrypto, CryptoKey } from 'webcrypto-core';
import EllipticCurveKey from './EllipticCurveKey';
import base64url from 'base64url';
import { SubtleCryptoExtension } from 'verifiablecredentials-crypto-sdk-typescript-plugin';
const utils = require('minimalistic-crypto-utils');
const EC = require('elliptic');
const eddsa = EC.eddsa;

/**
 * Wrapper class to integrate elliptic into web crypto
 */
export default class EllipticEdDsaProvider extends EllipticDsaProvider {
  /**
   *
   * Gets the name of the provider
   */
  public readonly name = 'EdDSA';

  /**
   * Different curves supported by the package
   */
  public namedCurves = ['ed25519'];

  /**
   * Different usages supported by the provider
   */
  public usages: any = {
    privateKey: ['sign', 'verify']
  };

  constructor(private crypto: SubtleCrypto) {
    super(crypto);
  }

  /**
   * The ECDSA signature implementation
   * @param algorithm used for signing
   * @param key used for signing
   * @param data to sign
   */
  async onSign(algorithm: EcdsaParams, key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const keyPair = (<EllipticCurveKey>key).key;
    
    const dataToSign = Buffer.from(data);
    const signature = new Buffer(keyPair.sign(Buffer.from(dataToSign)).toHex(), 'hex');
    const r = signature.slice(0, 32);
    const s = signature.slice(32);
    if ((<any>algorithm).format === 'DER') {
      return SubtleCryptoExtension.toDer([r, s]);
    }

    return new Uint8Array(Buffer.concat([r, s]));  
  }

  /**
   * The ECDSA signature verification
   * @param algorithm used for signing
   * @param key used for verify
   * @param signature to validate
   * @param data which was signed sign
   */
  async onVerify(_algorithm: EcdsaParams, key: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    const ecKey = (<EllipticCurveKey>key).key;
    data = Buffer.from(data);
    const hexData = utils.encode(data, 'hex');

    let signed = new Uint8Array(signature);
    if (signature.byteLength > 65) {
      // DER formatted
      const decodedSignature = SubtleCryptoExtension.fromDer(signed);
      signed = new Uint8Array(decodedSignature[0].length + decodedSignature[1].length);
      signed.set(decodedSignature[0]);
      signed.set(decodedSignature[1], decodedSignature[1].length);
    }
    
    const hexSignature = utils.encode(signed, 'hex');
    return ecKey.verify(data, hexSignature);  
  }

  /**
   * Generate key pair
   * @param algorithm for key generation
   * @param extractable is true if the key is exportable
   * @param keyUsages sign or verify
   */
  async onGenerateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    const ec = this.getCurve(algorithm.namedCurve);
    const random: any = await this.crypto.generateKey(<AesKeyGenParams>{ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
    let seed = (await this.crypto.exportKey('jwk', random)).k
    seed = utils.encode(base64url.toBuffer(seed!), 'hex');
    const key = ec.keyFromSecret(seed);
    //const pubBytes = key.getPublic(false, 'hex');
    //const privBytes = key.getPrivate('hex');
    const privateKey: any = CryptoKey.create(algorithm, 'private', extractable, keyUsages);
    privateKey.key = key;
    const publicKey: any = CryptoKey.create(algorithm, 'public', extractable, keyUsages);
    publicKey.key = key;

    return <CryptoKeyPair>{ privateKey, publicKey };
  }

  /**
   * Import jwk key
   * @param format must be 'jwk'
   * @param key Key to export in jwk
   * @param algorithm for key generation
   * @param extractable is true if the key is exportable
   * @param keyUsages sign or verify
   */
  async onImportKey(format: KeyFormat,
    keyData: JsonWebKey | ArrayBuffer, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    if (format !== 'jwk') {
      return Promise.reject(new Error(`Import key only supports jwk`));
    }
    const ec = this.getCurve(algorithm.namedCurve);
    const jwkKey: any = <JsonWebKey>keyData;
    let key: any = {};
    if (jwkKey.d) {
      const hexKey = utils.encode(base64url.toBuffer(jwkKey.d), 'hex');
      key = ec.keyFromSecret(hexKey);
      const privateKey: any = CryptoKey.create(algorithm, 'private', extractable, keyUsages);
      privateKey.key = key;
      return privateKey;
    } else {
      const hexKey = utils.encode(base64url.toBuffer(jwkKey.x), 'hex');
      key = ec.keyFromPublic(hexKey);
      const publicKey: any = CryptoKey.create(algorithm, 'public', extractable, keyUsages);
      publicKey.key = key;
      return publicKey
    }
  }

  /**
   * Export key to jwk
   * @param format must be 'jwk'
   * @param key Key to export in jwk
   */
  async onExportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    //const ec = this.getCurve((<any>key.algorithm).namedCurve);
    if (format !== 'jwk') {
      return Promise.reject(new Error(`Export key only supports jwk`));
    }

    const ecKey: any = (<EllipticCurveKey>key).key;
    const crv = (<any>key.algorithm).namedCurve;
    let x;
    const jwk: any = {
      crv,
      use: 'sig',
      alg: 'EdDSA',
      kty: 'OKP'
    }
    if (key.type === 'public') {
      jwk['x'] = base64url.encode(ecKey.getPublic('hex'), 'hex');
    } else {
      jwk['d'] = base64url.encode(ecKey.getSecret('hex'), 'hex');
      jwk['x'] = base64url.encode(ecKey.getPublic('hex'), 'hex');
    }

    return jwk;
  }

  /**
   * Get the instance that implements the algorithm
   * @param name Name of the algorithm
   */
  public getCurve(name: string): any {
    if (name.toLocaleLowerCase() === 'ed25519') {
      return new eddsa('ed25519');;
    }
    
    throw new Error(`The requested curve '${name}' is not supported in EllipticEcDsaProvider`);
  }
}
