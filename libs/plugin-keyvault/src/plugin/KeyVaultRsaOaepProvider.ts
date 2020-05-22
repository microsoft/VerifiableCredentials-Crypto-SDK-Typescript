/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { SubtleCrypto } from 'verifiablecredentials-crypto-sdk-typescript-plugin';
import { CryptoKey } from 'webcrypto-core';
import { RsaSubtleKey } from 'verifiablecredentials-crypto-sdk-typescript-keys';
import { IKeyStore } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
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
    privateKey: ['decrypt']
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
  async onDecrypt (_algorithm: Algorithm, key: RsaSubtleKey, data: ArrayBuffer): Promise<ArrayBuffer> {
    const rsaKey: JsonWebKey = key.key;
    const kid = (<any>rsaKey).kid;
    if (!kid) {
      throw new Error('kid is missing in the CryptoKey');
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
  async onGenerateKey (algorithm: RsaKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    const key = await this.generate('RSA', algorithm, extractable, keyUsages);
    return new RsaSubtleKey(algorithm, extractable, keyUsages, 'public', key);
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
    keyData: JsonWebKey, algorithm: RsaKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
    if (format !== 'jwk') {
      throw new Error(`Import key only supports jwk`);
    }
    let keyType = 'public';
    // Make sure the key elements are buffers
    if (typeof (keyData as any).e === 'string') {
      (keyData as any).e = base64url.toBuffer((keyData as any).e);
    }
    if (typeof (keyData as any).n === 'string') {
      (keyData as any).n = base64url.toBuffer((keyData as any).n);
    }

    return new Promise((resolve) => {
      resolve(new RsaSubtleKey(algorithm, extractable, keyUsages, keyType as any, keyData));
    });
  }

  /**
   * Export key to jwk
   * @param format must be 'jwk'
   * @param key Key to export in jwk
   */
  async onExportKey (format: KeyFormat, key: CryptoKey): Promise<JsonWebKey> {
    if (format !== 'jwk') {
      throw new Error(`Export key only supports jwk`);
    }

    const jwkKey = (key as RsaSubtleKey).key || (key as RsaSubtleKey);
    const kid = jwkKey.kid;

    let e = jwkKey.e;
    if (typeof e !== 'string') {
      e = base64url.encode(e);
    }

    let n = jwkKey.n;
    if (typeof n !== 'string') {
      n = base64url.encode(n);
    }

    const jwk = {
      kty: 'RSA',
      use: 'enc',
      kid,
      e,
      n
    };

    return new Promise((resolve) => resolve(jwk as JsonWebKey));
  }

  /**
   * Import jwk key
   * @param format must be 'jwk'
   * @param key Key to export in jwk
   * @param algorithm for key generation
   * @param extractable is true if the key is exportable
   * @param keyUsages sign or verify
   */
  public async toRsaKey (keyData: JsonWebKey, algorithm: RsaKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<RsaSubtleKey> {
    const jwkKey: any = keyData;
    return new RsaSubtleKey(algorithm, extractable,keyUsages, 'public', await this.onExportKey('jwk', jwkKey));
  }
}
