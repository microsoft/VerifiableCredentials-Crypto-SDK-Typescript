/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import base64url from 'base64url';
import { Subtle, IKeyGenerationOptions } from 'verifiablecredentials-crypto-sdk-typescript-plugin';
import { CryptoKey } from 'webcrypto-core';
import KeyVaultProvider from './KeyVaultProvider';
import KeyStoreKeyVault from '../keyStore/KeyStoreKeyVault';
import { IKeyStore, CryptoError, KeyReference, KeyStoreOptions } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import { JsonWebKey, IKeyContainer } from 'verifiablecredentials-crypto-sdk-typescript-keys';
import { SignResult } from '@azure/keyvault-keys';

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
    subtle: Subtle,
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

    const kid = (<any>key.algorithm).kid;
    if (!kid) {
      throw new CryptoError(algorithm, 'Missing kid in algortihm');
    }

    const client = (<KeyStoreKeyVault>this.keyStore).getCryptoClient(kid);

    let signature: SignResult;
    try {
      signature = await client.sign(<any>'ES256K', new Uint8Array(hash));
    } catch (exception) {
      if (exception.message.startsWith('Key and signing algorithm are incompatible')) {
        // Added for legacy. Used by keys generated with crv: SECP256K1
        signature = await client.sign(<any>'ECDSA256', new Uint8Array(hash));
      } else {
        throw exception;
      }
    }

    return signature.result;
  }

  /**
   * Import jwk key. Return @class CryptoKey as the internal format of a key.
   * This method does not import any key material into key vault.
   * @param format must be 'jwk'
   * @param jwk Key to export in jwk
   * @param algorithm for key generation
   * @param extractable is true if the key is exportable
   * @param keyUsages sign or verify
   */
  async onImportKey(format: KeyFormat,
    jwk: JsonWebKey, _algorithm: EcKeyImportParams, _extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {

    if (format !== 'jwk') {
      throw new Error(`Import key only supports jwk`);
    }

    if (jwk.kty?.toUpperCase() !== 'EC') {
      throw new Error(`Import key only supports kty EC`);
    }

    if (jwk.crv?.toUpperCase() === 'SECP256K1') {
      jwk.crv = 'P-256K';
    } else if (jwk.crv?.toUpperCase() !== 'P-256K') {
      throw new Error(`Import key only supports crv P-256K`);
    }

    if (!jwk.kid && jwk.kid!.startsWith('https://')) {
      throw new Error(`Imported key must have a kid in the format https://<vault>/keys/<name>/<version>`);
    }

    const kidParts = jwk.kid!.split('/');
    let secretType: boolean = kidParts[3] === 'secrets';

    if (!['keys', 'secrets'].includes(kidParts[3])) {
      throw new Error(`Imported key must be of type keys or secrets`);
    }

    if (kidParts.length <= 5) {
      const container: IKeyContainer = (await (<KeyStoreKeyVault>this.keyStore).get(new KeyReference(kidParts[4], secretType ? KeyStoreKeyVault.SECRETS : KeyStoreKeyVault.KEYS), new KeyStoreOptions({ latestVersion: true })));
      const kvKey = container.getKey<JsonWebKey>();
      jwk.kid = kvKey.kid;
    }

    const alg = <EcKeyAlgorithm>this.subtle.algorithmTransform({
      name: "ECDSA",
      namedCurve: "P-256K",
    });

    // convert key to crypto key
    const cryptoKey: CryptoKey = await this.subtle.importKey(
      'jwk',
      jwk,
      alg,
      true,
      keyUsages);

    // need to keep track of kid. cryptoKey is not extensible
    (<any>cryptoKey.algorithm).kid = jwk.kid;

    return cryptoKey;
  }

  /**
   * Generate key pair. Return @class CryptoKey as @class EllipticCurveSubtleKey.
   * EllipticCurveSubtleKey is the internal format for all keys
   * @param algorithm for key generation
   * @param extractable is true if the key is exportable
   * @param keyUsages sign or verify
   */
  async onGenerateKey(algorithm: EcKeyGenParams, extractable: boolean, keyUsages: KeyUsage[], options?: IKeyGenerationOptions): Promise<CryptoKeyPair> {
    if (!options) {
      options = { curve: 'P-256K' }
    } else {
      options.curve = 'P-256K';
    }

    const [name, publicKey] = await this.generate('EC', algorithm, extractable, keyUsages, options);
    const jwk: any = {
      kid: publicKey.id,
      kty: 'EC',
      use: 'sig',
      x: base64url.encode(publicKey.key.x),
      y: base64url.encode(publicKey.key.y),
      alg: 'ES256K',
      crv: 'P-256K'
    };

    const alg = <EcKeyAlgorithm>this.subtle.algorithmTransform({
      name: "ECDSA",
      namedCurve: "P-256K",
    });

    // convert key to crypto key
    const cryptoKey: any = await this.subtle.importKey(
      'jwk',
      jwk,
      alg,
      true,
      keyUsages);
    
    // need to keep track of kid. cryptoKey is not extensible
    (<any>cryptoKey.algorithm).kid = jwk.kid;

    // Save public key in cach
    await (<KeyStoreKeyVault>this.keyStore).cache.save(new KeyReference(name, KeyStoreKeyVault.KEYS), jwk);

    const pair = <CryptoKeyPair>{ publicKey: cryptoKey };
    return pair;
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
    return <Promise<JsonWebKey>>this.subtle.exportKey(format, key);
  }
}