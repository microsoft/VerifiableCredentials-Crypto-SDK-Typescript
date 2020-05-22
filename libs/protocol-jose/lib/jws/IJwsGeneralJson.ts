/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { ProtectionFormat } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import { TSMap } from 'typescript-map'
import IJwsSignature from './IJwsSignature';

/**
 * Defines a header in JWS
 */
export type JwsHeader = TSMap<string, string>;

/**
 * JWS general json format
 */
export default interface IJwsGeneralJson {

  /**
   * The application-specific non-encoded payload.
   */
  payload: Buffer,

  /**
   * The signatures
   */
  signatures: IJwsSignature[],

  /**
   * The serialization format
   */
  format: ProtectionFormat
}
