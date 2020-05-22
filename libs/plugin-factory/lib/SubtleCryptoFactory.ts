/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { TokenCredential } from '@azure/identity';
import { SubtleCryptoNode } from 'verifiablecredentials-crypto-sdk-typescript-plugin';
import { CryptoError } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import { SubtleCrypto } from 'verifiablecredentials-crypto-sdk-typescript-plugin';
import { SubtleCryptoKeyVault } from 'verifiablecredentials-crypto-sdk-typescript-plugin-keyvault';
import KeyStoreFactory from './KeyStoreFactory';

/**
 * Data mapper factory
 */
export default class SubtleCryptoFactory {

  /**
   * Saves the specified data blob into the data mapper
   * @param subtleName The name of the subtle crypto.
   * @param credential The azure token credential
    */
  static create (subtleName: string, credential?: TokenCredential, vaultUri?: string): SubtleCrypto {
    switch (subtleName) {
      case 'SubtleCryptoNode': 
        return SubtleCryptoNode.getSubtleCrypto();
      case 'SubtleCryptoKeyVault': 
        const subtle = new SubtleCrypto();
        const keyStore = KeyStoreFactory.create('KeyStoreKeyVault', credential, vaultUri);
        return new SubtleCryptoKeyVault(subtle, keyStore).getSubtleCrypto();
      default:
        throw new CryptoError(<any>undefined,`Subtle crypto '${subtleName}' not found`);
    }
  }
}
