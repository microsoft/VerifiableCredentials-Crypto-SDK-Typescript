/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { SubtleCryptoElliptic } from '@microsoft/crypto-subtle-plugin-elliptic';
import CryptoFactory from './CryptoFactory';
import { IKeyStore } from '@microsoft/crypto-keystore';
import { SubtleCrypto } from './index';

/**
 * Crypto operations class to return Elliptic subtle crypto
 */
export default class EllipticCryptoOperations extends CryptoFactory {
  private elliptic: any;

  constructor(keyStore: IKeyStore, crypto: any) {
    super(keyStore, crypto);
    this.elliptic = new SubtleCryptoElliptic(crypto);
  }
  /**
   * Gets all of the message signing Algorithms from the plugin
  * @returns a subtle crypto object for message signing
    */
   public getMessageSigners (): SubtleCrypto {
    return this.elliptic;
  }   
}
