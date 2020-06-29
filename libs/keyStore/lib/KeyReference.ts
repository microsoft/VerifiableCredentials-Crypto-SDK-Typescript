/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { CryptoKey } from 'webcrypto-core'

/**
 * Class to model the key reference
 */
export default class KeyReference {
  /**
   * Create an instance of <see @class KeyReference>
   * @param keyReference Name of the key
   * @param extractable True if the key is extractable
   * @param cryptoKey Reference to a key in an external system
   */
  constructor(public keyReference: string, public type: string = 'key', public cryptoKey?: CryptoKey) {
  }
}
