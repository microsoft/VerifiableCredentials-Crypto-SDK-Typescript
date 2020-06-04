/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { SubtleCrypto } from 'verifiablecredentials-crypto-sdk-typescript-plugin';
import { CryptoKey } from 'webcrypto-core';
import { IKeyStore, CryptoError } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import base64url from 'base64url';
import KeyVaultProvider from './KeyVaultProvider';
import KeyStoreKeyVault from '../keyStore/KeyStoreKeyVault';

/**
 * Wrapper class for key vault plugin
 */
export default class KeyVaultRsaOaepProvider extends KeyVaultProvider {
  /**
   *
   * Gets the name of the provider
   */
  public readonly name = 'RSA-OAEP';

  /**
   * Different usages supported by the provider
   */
  public usages: any = {
    privateKey: ['decrypt', 'encrypt']
  };

  /**
   * Create a new instance of @class KeyVaultRsaOaepProvider
   * @param crypto A default subtle crypto object. Can be used for local crypto functions
   * @param keyStore The key vault key store
   */
  constructor (
    crypto: SubtleCrypto,
    keyStore: IKeyStore) {
    super(crypto, keyStore);
  }

  /**
   * The RSA decryption implementation
   * @param algorithm used for decryption
   * @param key used for decryption
   * @param data to decrypt
   */
  async onDecrypt (algorithm: Algorithm, key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const kid = (<any>key.algorithm).kid;
    if (!kid) {
      throw new CryptoError(algorithm, 'Missing kid in algortihm');
    }

    const client = (<KeyStoreKeyVault>this.keyStore).getCryptoClient(kid);

    const payload = await client.decrypt('RSA-OAEP-256', new Uint8Array(data));
    return payload.result;
  }

  /**
   * Generate key pair
   * @param algorithm for key generation
   * @param extractable is true if the key is exportable
   * @param keyUsages sign or verify
   */
  async onGenerateKey (algorithm: RsaKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
    const publicKey: any = await this.generate('RSA', algorithm, extractable, keyUsages);
    const jwk = {
      kid: publicKey.id,
      kty: 'RSA',
      use: 'enc',
      e: base64url.encode(publicKey.key.e),
      n: base64url.encode(publicKey.key.n)
    };
    const cryptoKey = await this.subtle.importKey('jwk', jwk, algorithm, extractable, keyUsages);

    // need to keep track of kid. cryptoKey is not extensible
    (<any>cryptoKey.algorithm).kid = jwk.kid;
    const pair = <CryptoKeyPair> {publicKey: cryptoKey};
    return pair;
  }
  /**
   * Import jwk key. Return @class CryptoKey as the internal format of a key.
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

    return this.subtle.importKey(format, keyData, algorithm, extractable,keyUsages);
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
    return <JsonWebKey>this.subtle.exportKey(format, key);
  }
}
