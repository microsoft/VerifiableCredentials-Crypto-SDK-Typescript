/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { ProviderCrypto, SubtleCrypto } from 'webcrypto-core';
import EllipticEdDsaProvider from './EllipticEdDsaProvider';
import EllipticEcDsaProvider from './EllipticEcDsaProvider';

/**
 * Subtle crypto class
 */
export default class SubtleCryptoElliptic extends SubtleCrypto {
  /**
   * Constructs a new instance of the class.
   */
  constructor (crypto: any) {
    super();

      // Add EC provider to SubtleCrypto
      this.providers.set(<ProviderCrypto>new EllipticEcDsaProvider(crypto));
      this.providers.set(new EllipticEdDsaProvider(crypto));
    }
}
