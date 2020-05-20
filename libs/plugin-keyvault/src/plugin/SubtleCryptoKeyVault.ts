/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { SubtleCrypto } from 'webcrypto-core';
import { IKeyStore } from '@microsoft/crypto-keystore';
import KeyVaultEcdsaProvider from './KeyVaultEcdsaProvider';
import KeyVaultRsaOaepProvider from './KeyVaultRsaOaepProvider';

/**
 * Subtle crypto class
 */
export default class SubtleCryptoKeyVault extends SubtleCrypto {
  /**
   * Create a new instance of @class SubtleCryptoKeyVault
   * @param subtle A default subtle crypto object. Can be used for local crypto functions
   * @param keyStore The key vault key store
   */
  constructor (
    private subtle: any,
    private keyStore: IKeyStore) {
    super();

      // Add key vault provider to SubtleCrypto
    this.providers.set(new KeyVaultEcdsaProvider(this.subtle, this.keyStore));
    this.providers.set(new KeyVaultRsaOaepProvider(this.subtle, this.keyStore));
  }
}
