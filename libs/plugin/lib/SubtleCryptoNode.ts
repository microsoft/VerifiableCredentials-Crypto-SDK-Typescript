/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { SubtleCrypto } from './index';
import { ISubtleCrypto } from './ISubtleCryptoExtension';
const { Crypto } = require("@peculiar/webcrypto");
// var WebCrypto = require("node-webcrypto-ossl");

/**
 * Subtle crypto for node
 *  */
 export default class SubtleCryptoNode implements ISubtleCrypto {
  private static crypto: SubtleCrypto = new SubtleCrypto();

/**
 * Returns the @class SubtleCrypto implementation for the nodes environment
 */
 public getSubtleCrypto(): any {
  return SubtleCryptoNode.getSubtleCrypto();
}   

/**
 * Returns the @class SubtleCrypto implementation for the nodes environment
 */
  public static getSubtleCrypto(): any {
    return SubtleCryptoNode.crypto;
  }   
}
