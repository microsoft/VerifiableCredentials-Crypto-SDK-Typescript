/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { SubtleCrypto } from 'webcrypto-core';

/**
 * Interface for the Subtle Crypto 
 */
export default interface ISubtleCrypto {

  /**
   * Returns the @class SubtleCryptoBase implementation for the nodes environment
   */
  getSubtleCrypto(): SubtleCrypto;

  /**
   * Normalize the algorithm so it can be used by underlying crypto.
   * @param algorithm Algorithm to be normalized
   */
  algorithmTransform(algorithm: any): any;

  /**
 * Normalize the JWK parameters so it can be used by underlying crypto.
 * @param jwk Json web key to be normalized
 */
  keyImportTransform(jwk: any): any;

  /**
   * Normalize the JWK parameters from the underlying crypto so it is normalized to standardized parameters.
   * @param jwk Json web key to be normalized
   */
  keyExportTransform(jwk: any): any;

}
