/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { EllipticCurveSubtleKey, KeyType } from 'verifiablecredentials-crypto-sdk-typescript-keys';
import base64url from 'base64url';
import { SubtleCrypto } from 'verifiablecredentials-crypto-sdk-typescript-plugin';
import { CryptoKey } from 'webcrypto-core';
import KeyVaultProvider from './KeyVaultProvider';
import KeyStoreKeyVault from '../keyStore/KeyStoreKeyVault';
import { IKeyStore, KeyStoreInMemory } from 'verifiablecredentials-crypto-sdk-typescript-keystore';

/**
 * Wrapper class for key vault plugin
 */
export default class KeyVaultEcdsaProvider extends KeyVaultProvider {
  /**
   *
   * Gets the name of the provider
   */
  public readonly name = 'ECDSA';

  /**
   * Different usages supported by the provider
   */
  public usages: any = {
    privateKey: ['sign', 'verify']
  };

  /**
   * Create a new instance of @class KeyVaultEcdsaProvider
   * @param crypto A default subtle crypto object. Can be used for local crypto functions
   * @param keyStore The key vault key store
   */
  constructor(
    subtle: SubtleCrypto,
    keyStore: IKeyStore) {
    super(subtle, keyStore);
  }

  /**
   * The ECDSA signature implementation
   * @param algorithm used for signing
   * @param key used for signing
   * @param data to sign
   */
  async onSign(algorithm: EcdsaParams, key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    let hashAlgorithm = (typeof algorithm.hash === 'object' ? algorithm.hash.name || 'SHA-256' : algorithm.hash || 'SHA-256');
    const hash = await this.subtle.digest({ name: hashAlgorithm }, data);

    const client = (<KeyStoreKeyVault>this.keyStore).getCryptoClient((<any>key).key.kid);
    const signature = await client.sign(<any>'ECDSA256', new Uint8Array(hash));
    return signature.result;
  }

  /**
   * Generate key pair. Return @class CryptoKey as @class EllipticCurveSubtleKey.
   * EllipticCurveSubtleKey is the internal format for all keys
   * @param algorithm for key generation
   * @param extractable is true if the key is exportable
   * @param keyUsages sign or verify
   */
  async onGenerateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[], options?: any): Promise<CryptoKeyPair> {
    if (!options) {
      options = { curve: 'SECP256K1' }
    } else {
      options.curve = 'SECP256K1';
    }

    const keyPair = await this.generate('EC', algorithm, extractable, keyUsages, options);
    return keyPair;
  }

  /**
   * Import jwk key. Return @class EllipticCurveSubtleKey as the internal format of a key.
   * @param format must be 'jwk'
   * @param key Key to export in jwk
   * @param algorithm for key generation
   * @param extractable is true if the key is exportable
   * @param keyUsages sign or verify
   */
  async onImportKey(format: KeyFormat,
    keyData: JsonWebKey, algorithm: EcKeyImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    if (format !== 'jwk') {
      throw new Error(`Import key only supports jwk`);
    }

    let keyType: 'public' | 'private' = 'public';
    // Make sure the key elements are buffers
    if (typeof (keyData as any).x === 'string') {
      (keyData as any).x = base64url.toBuffer((keyData as any).x);
    }
    if (typeof (keyData as any).y === 'string') {
      (keyData as any).y = base64url.toBuffer((keyData as any).y);
    }
    if (typeof (keyData as any).d === 'string') {
      keyType = 'private';
      (keyData as any).d = base64url.toBuffer((keyData as any).d);
    }

    return new Promise((resolve) => {
      resolve(KeyVaultEcdsaProvider.toCryptoKey(this.subtle, algorithm, keyType, extractable, keyUsages, keyData));
    });
  }

  /**
   * Export key to jwk
   * @param format must be 'jwk'
   * @param key Key to export in jwk
   */
  async onExportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey> {
    if (format !== 'jwk') {
      throw new Error(`Export key only supports jwk`);
    }

    const jwkKey = (key as EllipticCurveSubtleKey).key;
    const kid = jwkKey.kid;
    const crv = jwkKey.crv;
    let x = jwkKey.x;
    if (typeof x !== 'string') {
      x = base64url.encode(x);
    }
    let y = jwkKey.y;
    if (typeof y !== 'string') {
      y = base64url.encode(y);
    }

    const jwk = {
      kid,
      kty: 'EC',
      use: 'sig',
      crv,
      x,
      y
    };

    return new Promise((resolve) => resolve(jwk as JsonWebKey));
  }


  /**
   * Convert to CryptoKey
   * @param algorithm for key generation
   * @param extractable is true if the key is exportable
   * @param keyUsages sign or verify
   * @param key to convert
   */
  public static async toCryptoKey(subtle: SubtleCrypto, algorithm: EcKeyGenParams, type: 'public' | 'private', extractable: boolean, keyUsages: KeyUsage[], key: any): Promise<CryptoKey> {
    const cryptoKey: any = CryptoKey.create(algorithm, type, extractable, keyUsages);
    cryptoKey.key = key;

    // import/export key to make sure subtlecrypto is aware of the key.
    subtle.importKey('jwk',
      await subtle.exportKey('jwk', cryptoKey),
      algorithm,
      true,
      keyUsages);
    return cryptoKey;
  }

  /**
   * Convert to CryptoKeyPair
   * @param algorithm for key generation
   * @param extractable is true if the key is exportable
   * @param keyUsages sign or verify
   * @param key to convert
   */
  public static async toCryptoKeyPair(subtle: SubtleCrypto, algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[], key: any): Promise<CryptoKeyPair> {
    const cryptoKey = await KeyVaultEcdsaProvider.toCryptoKey(subtle, algorithm, 'public', extractable, keyUsages, key);
    const pair = {
      publicKey: cryptoKey
    };
    return <CryptoKeyPair>pair;
  }
}
