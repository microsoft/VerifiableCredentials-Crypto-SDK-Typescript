/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { CryptoFactoryNode } from 'verifiablecredentials-crypto-sdk-typescript-plugin-cryptofactory-suites';
import { CryptoFactoryKeyVault } from 'verifiablecredentials-crypto-sdk-typescript-plugin-keyvault';
import { CryptoError, IKeyStore } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import { Subtle, CryptoFactory } from 'verifiablecredentials-crypto-sdk-typescript-plugin';

/**
 * Crypto factory mapper
 */
export default class CryptoFactoryManager {

  /**
   * Create the crypto factory instance
   * @param cryptoFactoryName The name of the crypto factory.
   * @param keyStore used to store private keys.
   * @param crypto Default subtle crypto used for e.g. hashing.
    */
  static create (cryptoFactoryName: string, keyStore: IKeyStore, crypto: Subtle): CryptoFactory {
    switch (cryptoFactoryName) {
      case 'CryptoFactoryNode': 
        return new CryptoFactoryNode(keyStore, crypto);
      case 'CryptoFactoryKeyVault': 
        return new CryptoFactoryKeyVault(keyStore, crypto);
      default:
        throw new CryptoError(<any>undefined,`Crypto factory '${cryptoFactoryName}' not found`);
    }
  }
}
