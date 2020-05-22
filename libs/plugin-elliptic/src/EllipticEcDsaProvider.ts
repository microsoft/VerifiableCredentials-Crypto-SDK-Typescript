/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

const EC = require('elliptic').ec;
import EllipticDsaProvider from './EllipticDsaProvider';
import { SubtleCrypto } from 'webcrypto-core';
import EllipticCurveKey from './EllipticCurveKey';
import base64url from 'base64url';
const shajs = require('sha.js');
const clone = require('clone');

/**
 * Wrapper class to integrate elliptic into web crypto
 */
export default class EllipticEcDsaProvider extends EllipticDsaProvider {
  /**
   *
   * Gets the name of the provider
   */
  public readonly name = 'ECDSA';

  /**
   * Different curves supported by the package
   */
  public namedCurves = ['secp256k1', 'K-256'];

  /**
   * secp256k1 elliptic type
   */
  private secp256k1: any;

  constructor (crypto: SubtleCrypto) {
    super(crypto);

    this.secp256k1 = new EC('secp256k1');
  }

/**
   * Generate key pair
   * @param algorithm for key generation
   * @param extractable is true if the key is exportable
   * @param keyUsages sign or verify
   */
  async onGenerateKey (algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    const ec = this.getCurve(algorithm.namedCurve);
    const keyPair = ec.genKeyPair();
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
    let hashAlgortihm = (typeof algorithm.hash === 'object' ? algorithm.hash.name || 'sha256' : algorithm.hash || 'sha256').replace('-','');
    const hash = shajs(hashAlgortihm).update(data);
    const signature = ecKey.sign(hash.digest);
    const r = signature.r.toArray();
    const s = signature.s.toArray();
    if ((<any>algorithm).format === 'DER') {
      return EllipticDsaProvider.toDer([r, s]);
    }

    return new Uint8Array(r.concat(s));
  }
 /**
   * The ECDSA signature verification
   * @param algorithm used for signing
   * @param key used for verify
   * @param signature to validate
   * @param data which was signed sign
   */
  async onVerify (algorithm: EcdsaParams, key: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean> {
    const ecKey = (<EllipticCurveKey> key).key;
    data = Buffer.from(data);
    let hashAlgortihm = (typeof algorithm.hash === 'object' ? algorithm.hash.name || 'sha256' : algorithm.hash || 'sha256').replace('-','');
    const hash = shajs(hashAlgortihm).update(data);

    let signed = new Uint8Array(signature);
    if (signature.byteLength <= 64) {
      // Not DER formatted
      const r = signed.slice(0, signed.byteLength / 2);
      const s = signed.slice(signed.byteLength / 2, signed.byteLength)
      signed =  new Uint8Array(EllipticDsaProvider.toDer([r, s]));

    }

    let signArray = Array.from(signed);
    return ecKey.verify(hash.digest, signArray);
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
    const pubKey = cryptoKey.pub;
    const x = pubKey.x.toArrayLike(Buffer, 'be', 32);
    const y = pubKey.x.toArrayLike(Buffer, 'be', 32);

    const jwk: JsonWebKey = {
      kty: 'EC',
      use: 'sig',
      crv: (<any> key.algorithm).namedCurve,
      x: base64url.encode(x),
      y: base64url.encode(y)
    };

    if (key.type === 'private') {
      const privKey = cryptoKey.priv;
      jwk.d = base64url.encode(privKey.toArrayLike(Buffer, 'be', 32));
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
    const x = base64url.toBuffer(<string> jwkKey.x);
    const y = base64url.toBuffer(<string> jwkKey.y);
    const pubKey = ec.keyFromPublic({ x, y });
    if (jwkKey.d) {
      const d = base64url.toBuffer(jwkKey.d);
      const pair = ec.keyPair({ priv: d, pub: pubKey.pub });
      return new EllipticCurveKey(algorithm, extractable, keyUsages, 'private', pair);
    }

    const pair = ec.keyPair({ pub: pubKey.pub });
    return new EllipticCurveKey(algorithm, extractable, keyUsages, 'public', pair);
  }

  /**
   * Get the instance that implements the algorithm
   * @param name Name of the algorithm
   */
  public getCurve(name: string): any {
    if (name.toLocaleLowerCase() === 'secp256k1' || name.toUpperCase() === 'P-256K') {
      return this.secp256k1;
    }
    
    throw new Error(`The requested curve '${name}' is not supported in EllipticEcDsaProvider`);
  }
}
