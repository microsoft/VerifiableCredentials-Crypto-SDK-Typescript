/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import EllipticDsaProvider from './EllipticDsaProvider';
import { SubtleCrypto, CryptoKey } from 'webcrypto-core';
import EllipticCurveKey from './EllipticCurveKey';
import base64url from 'base64url';
const clone = require('clone');
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
  public readonly name = 'EDDSA';

  /**
   * Different curves supported by the package
   */
  public namedCurves = ['ed25519'];
  
  constructor (private crypto: SubtleCrypto) {
    super(crypto);
  }

  /**
   * Generate key pair
   * @param algorithm for key generation
   * @param extractable is true if the key is exportable
   * @param keyUsages sign or verify
   */
  async onGenerateKey (algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    const ec = this.getCurve(algorithm.namedCurve);
    const random: any  = await this.crypto.generateKey(<AesKeyGenParams>{name: 'AES-GCM', length: 256}, true, ['encrypt']);
    const seed = await (await this.crypto.exportKey('jwk', random)).k;
    const keyPair = ec.keyFromSecret(seed);
    if (!keyPair.pub) {
      keyPair.pub = keyPair.getPublic();
    }

    // Set private key
    const privateKey: CryptoKey = new EllipticCurveKey(algorithm, extractable, keyUsages, 'private', keyPair);

    // Set public key
    const pubKey = clone(keyPair);
    delete pubKey.priv;
    const publicKey: CryptoKey = new EllipticCurveKey(algorithm, extractable, keyUsages, 'public', pubKey);
    return <CryptoKeyPair>{ privateKey, publicKey };
  }

  /**
   * The ECDSA signature implementation
   * @param algorithm used for signing
   * @param key used for signing
   * @param data to sign
   */
  async onSign (algorithm: EcdsaParams, key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const ecKey = (<EllipticCurveKey> key).key;
    data = Buffer.from(data);
    //(<any> data).length = data.byteLength;
    const signature = new Buffer(ecKey.sign(Buffer.from(data)).toHex(), 'hex');
    const r = signature.slice(0, 32);
    const s = signature.slice(32);
    if ((<any>algorithm).format === 'DER') {
      return EllipticDsaProvider.toDer([r, s]);
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
  async onVerify (_algorithm: EcdsaParams, key: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    const ecKey = (<EllipticCurveKey> key).key;
    data = Buffer.from(data);

    let signed = new Uint8Array(signature);
    if (signature.byteLength > 65) {
      // DER formatted
      const decodedSignature = EllipticDsaProvider.fromDer(signed);
      signed = new Uint8Array(decodedSignature[0].length + decodedSignature[1].length);
      signed.set(decodedSignature[0]);
      signed.set(decodedSignature[1], decodedSignature[1].length);
    } 

    const encoded = utils.encode(signed, 'hex');
    return ecKey.verify(Buffer.from(data), encoded);
  }

  /**
   * Export key to jwk
   * @param format must be 'jwk'
   * @param key Key to export in jwk
   */
  async onExportKey (format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
    //const ec = this.getCurve((<any>key.algorithm).namedCurve);
    if (format !== 'jwk') {
      throw new Error(`Export key only supports jwk`);
    }

    const cryptoKey: any = (<EllipticCurveKey> key).key;
    const pubKey = cryptoKey.getPublic();
    const x = base64url.encode(pubKey);

    const jwk: JsonWebKey = {
      kty: 'OKP',
      use: 'sig',
      crv: (<any> key.algorithm).namedCurve,
      x: x
    };

    if (key.type === 'private') {
      const privKey = cryptoKey.getSecret();
      jwk.d = base64url.encode(privKey);
    }

    return jwk;
  }
  
  /**
   * Import jwk key
   * @param format must be 'jwk'
   * @param key Key to export in jwk
   * @param algorithm for key generation
   * @param extractable is true if the key is exportable
   * @param keyUsages sign or verify
   */
  async onImportKey (format: KeyFormat,
    keyData: JsonWebKey | ArrayBuffer, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    if (format !== 'jwk') {
      throw new Error(`Import key only supports jwk`);
    }
    const ec = this.getCurve(algorithm.namedCurve);
    const jwkKey: JsonWebKey = <JsonWebKey> keyData;
    if (jwkKey.d) {
      const pair = ec.keyFromSecret(base64url.toBuffer(jwkKey.d));
      return new EllipticCurveKey(algorithm, extractable, keyUsages, 'private', pair);
    }

    // verify requires an array
    const x = Array.from(base64url.toBuffer(<string> jwkKey.x));
    const pubKey = ec.keyFromPublic(x);
    return new EllipticCurveKey(algorithm, extractable, keyUsages, 'public', pubKey);
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
