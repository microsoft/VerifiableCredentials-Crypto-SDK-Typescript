/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { ProviderCrypto } from 'webcrypto-core';

/**
 * Wrapper class to integrate elliptic into web crypto
 */
export default abstract class EllipticDsaProvider extends ProviderCrypto {

  /**
   * Different usages supported by the provider
   */
  public usages: any = {
    privateKey: ['sign'],
    publicKey: ['verify']
  };

  constructor ( _subtle: any) {
    super();
  }

  /**
   * Get the instance that implements the algorithm
   * @param name Name of the algorithm
   */
  abstract getCurve(name: string): any;
}
