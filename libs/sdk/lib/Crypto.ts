/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { CryptoBuilder, KeyUse, CryptoHelpers } from './index';

/**
 * Class to model Crypto
 */
export default class Crypto {

  private signingKey: CryptoKeyPair | CryptoKey | undefined;

  constructor(
    private _builder: CryptoBuilder) {
  } 

  /**
   * Gets the builder for the request
   */
  public get builder(): CryptoBuilder {
    return this._builder;
  }

  public async generateKey(keyUse: KeyUse) {
    if (keyUse === KeyUse.Signature) {
      const algorithm = CryptoHelpers.jwaToWebCrypto(this.builder.signingAlgorithm);

      this.signingKey = await this.builder.subtle.generateKey(
        algorithm, 
        this.builder.signingKeyOptions.extractable!,
        ['sign', 'verify'],
        {name: this.builder.signingKeyReference});
      
    } else {
      throw new Error('not implemented');
    }
  }
}

