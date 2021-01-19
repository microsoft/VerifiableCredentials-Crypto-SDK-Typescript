/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { Subtle } from 'verifiablecredentials-crypto-sdk-typescript-plugin';
import { CryptoKey } from 'webcrypto-core';
import { IKeyStore, CryptoError, KeyReference } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
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
    crypto: Subtle,
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
      return Promise.reject(new CryptoError(algorithm, 'Missing kid in algortihm'));
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
    const [name, publicKey] = await this.generate('RSA', algorithm, extractable, keyUsages);
    const jwk: any = {
      kid: publicKey.id,
      kty: 'RSA',
      use: 'enc',
      e: base64url.encode(publicKey.key.e),
      n: base64url.encode(publicKey.key.n)
    };

    // convert key to crypto key
    const cryptoKey = await this.subtle.importKey('jwk', jwk, algorithm, true, keyUsages);

    // need to keep track of kid. cryptoKey is not extensible
    (<any>cryptoKey.algorithm).kid = jwk.kid;
    
    // Save public key in cach
    await (<KeyStoreKeyVault>this.keyStore).cache.save(new KeyReference(name, KeyStoreKeyVault.KEYS), jwk);

    const pair = <CryptoKeyPair> {publicKey: cryptoKey};
    return pair;
  }
}
