/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { SubtleCrypto } from 'webcrypto-core';
import { IKeyStore } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import { ISubtleCrypto, IKeyGenerationOptions } from 'verifiablecredentials-crypto-sdk-typescript-plugin';
import KeyVaultEcdsaProvider from './KeyVaultEcdsaProvider';
import KeyVaultRsaOaepProvider from './KeyVaultRsaOaepProvider';
const clone = require('clone');

// Named curves
const CURVE_P256K = 'P-256K';
const CURVE_K256 = 'K-256';
const CURVE_SECP256K1 = 'SECP256K1';

/**
 * SubtleCrypto crypto class
 */
export default class SubtleCryptoKeyVault extends SubtleCrypto implements ISubtleCrypto {

  /**
   * Override generateKey to support additional options argument
   * @param algorithm for key generation
   * @param extractable True if key is extractable
   * @param keyUsages For the key
   * @param options Options used to define optional name
   */
  public async generateKey(algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[], options?: IKeyGenerationOptions) {
    //this.checkRequiredArguments(arguments, options ? 4 : 3, "generateKey");
    const preparedAlgorithm = this.prepareAlgorithm(algorithm);
    const provider: any = this.getProvider(preparedAlgorithm.name);
    const result = await provider.generateKey({ ...preparedAlgorithm, name: provider.name }, extractable, keyUsages, options);
    return result;
  }

  /**
   * Create a new instance of @class SubtleCryptoKeyVault
   * @param subtle A default subtle crypto object. Can be used for local crypto functions
   * @param keyStore The key vault key store
   */
  constructor(
    private subtle: any,
    private keyStore: IKeyStore) {
    super();

    // Add key vault provider to SubtleCrypto
    this.providers.set(new KeyVaultEcdsaProvider(this.subtle, this.keyStore));
    this.providers.set(new KeyVaultRsaOaepProvider(this.subtle, this.keyStore));
  }

  /**
   * Returns the @class SubtleCrypto implementation for the nodes environment
   */
  public getSubtleCrypto(): any {
    return this;
  }

    /**
     * Normalize the algorithm so it can be used by underlying crypto.
     * @param algorithm Algorithm to be normalized
     */
    public algorithmTransform(algorithm: any) {
      return algorithm;
  }

  /**
 * Normalize the JWK parameters so it can be used by underlying crypto.
 * @param jwk Json web key to be normalized
 */
  public keyImportTransform(jwk: any) {
      if (jwk.crv) {
          const curve = (<string>jwk.crv).toUpperCase();
          if (curve === CURVE_P256K) {
              const clonedKey = clone(jwk);
              clonedKey.crv = CURVE_SECP256K1;
              return clonedKey;
          }
      }

      return jwk;
  }

  /**
   * Normalize the JWK parameters from the underlying crypto so it is normalized to standardized parameters.
   * @param jwk Json web key to be normalized
   */
  public keyExportTransform(jwk: any) {
      if (jwk.crv) {
          const curve = (<string>jwk.crv).toUpperCase();
          if (curve === CURVE_P256K || curve === CURVE_K256) {
              const clonedKey = clone(jwk);
              clonedKey.crv = CURVE_SECP256K1;
              return clonedKey;
          }
      }

      return jwk;
  }
}
