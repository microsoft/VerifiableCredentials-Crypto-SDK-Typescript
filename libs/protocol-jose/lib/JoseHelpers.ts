/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { CryptoProtocolError } from 'verifiablecredentials-crypto-sdk-typescript-protocols-common';
import { KeyTypeFactory, KeyUseFactory, KeyType, KeyUse } from 'verifiablecredentials-crypto-sdk-typescript-keys';
import { CryptoHelpers } from 'verifiablecredentials-crypto-sdk-typescript-plugin';
import base64url from 'base64url';
import { JweHeader } from './jwe/IJweGeneralJson';
import { JwsHeader } from './jws/IJwsGeneralJson';
import { IJweEncryptionOptions, IJwsSigningOptions } from './IJoseOptions';
import JoseConstants from './JoseConstants';

/**
 * Crypto helpers support for plugable crypto layer
 */
export default class JoseHelpers {
  /**
   * Return true if the header has elements
   * @param header to test
   */
  public static headerHasElements(header: JweHeader | JwsHeader | undefined): boolean {
    if (!header) {
      return false;
    }

    if (header.length !== undefined) {
      return header.length > 0;
    }

    return Object.keys(header).length > 0;
  }

  /**
   * Encode the header to JSON and base 64 url.
   * The Typescript Map construct does not allow for JSON.stringify returning {}.
   * TSMap.toJSON prepares a map so it can be serialized as a dictionary.
   * @param header to encode
   * @param toBase64Url is true when result needs to be base 64 url
   */
  public static encodeHeader(header: JweHeader | JwsHeader, toBase64Url: boolean = true): string {
    const serializedHeader = JSON.stringify(header.toJSON());
    if (toBase64Url) {
      return base64url.encode(serializedHeader);
    }
    return serializedHeader;
  }

  /**
   * Get the Protected to be used from the options
   * @param propertyName Property name in options
   * @param [initialOptions] The initial set of options
   * @param [overrideOptions] Options passed in after the constructure
   * @param [mandatory] True if property is required
   */
  public static getOptionsProperty<T>(
    propertyName: string,
    initialOptions?: IJweEncryptionOptions | IJwsSigningOptions,
    overrideOptions?: IJweEncryptionOptions | IJwsSigningOptions,
    mandatory: boolean = true
  ): T {
    let overrideOption: T | undefined;
    let initialOption: T | undefined;

    if (overrideOptions) {
      overrideOption = <T>overrideOptions[propertyName];
    }
    if (initialOptions) {
      initialOption = <T>initialOptions[propertyName];
    }

    if (mandatory && !overrideOption && !initialOption) {
      throw new CryptoProtocolError(JoseConstants.Jose, `The property '${propertyName}' is missing from options`);
    }

    return overrideOption || <T>initialOption;
  }
    
  /**
   * Create the key use according to the selected algorithm.
   * @param algorithm JWA algorithm constant
   */
  public static createTypeViaJwa (algorithm: string): KeyType {
    const alg = CryptoHelpers.jwaToWebCrypto(algorithm);
    return KeyTypeFactory.createViaWebCrypto(alg);
  }
  
  /**
   * Create the key use according to the selected algorithm.
   * @param algorithm JWA algorithm constant
   */
  public static createUseViaJwa (algorithm: string): KeyUse {
    const alg = CryptoHelpers.jwaToWebCrypto(algorithm);
    return KeyUseFactory.createViaWebCrypto(alg);
  }

}
