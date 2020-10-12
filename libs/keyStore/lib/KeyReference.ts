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
   * @param keyReference Name of the key in DID document
   * @param extractable True if the key is extractable
   * @param remoteKeyReference Name of the key in a remote server such as key vault. Can be used when difference from DID document
   * @param cryptoKey Reference to a key in an external system
   */
  constructor(public keyReference: string, public type: string = 'secret', public remoteKeyReference?: string, public cryptoKey?: CryptoKey) {
  }
}
