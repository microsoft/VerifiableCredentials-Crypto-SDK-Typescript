/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { CryptoBuilder } from './index';

/**
 * Class to model Crypto
 */
export default class Crypto {

  constructor(
    private _builder: CryptoBuilder) {
  } 

  /**
   * Gets the builder for the request
   */
  public get builder(): CryptoBuilder {
    return this._builder;
  }
}

