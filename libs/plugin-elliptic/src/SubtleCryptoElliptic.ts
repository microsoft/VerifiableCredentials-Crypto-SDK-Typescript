/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { ProviderCrypto, SubtleCrypto } from 'webcrypto-core';
import { ISubtleCrypto } from 'verifiablecredentials-crypto-sdk-typescript-plugin';
import EllipticEdDsaProvider from './EllipticEdDsaProvider';
import EllipticEcDsaProvider from './EllipticEcDsaProvider';

/**
 * SubtleCrypto crypto class
 */
export default class SubtleCryptoElliptic extends SubtleCrypto implements ISubtleCrypto {
  /**
   * Constructs a new instance of the class.
   */
  constructor(crypto: any) {
    super();

    // Add EC provider to SubtleCrypto
    this.providers.set(<ProviderCrypto>new EllipticEcDsaProvider(crypto));
    this.providers.set(new EllipticEdDsaProvider(crypto));
  }

  checkRequiredArguments(args: any[], size: number, methodName: string) {
    if (methodName !== 'generateKey' && args.length !== size) {
      throw new TypeError(`Failed to execute '${methodName}' on 'SubtleCrypto': ${size} arguments required, but only ${args.length} present`);
    }
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
    return jwk;
  }

  /**
   * Normalize the JWK parameters from the underlying crypto so it is normalized to standardized parameters.
   * @param jwk Json web key to be normalized
   */
  public keyExportTransform(jwk: any) {
    return jwk;
  }

}
