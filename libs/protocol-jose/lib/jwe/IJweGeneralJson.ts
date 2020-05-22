/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import IJweRecipient from './IJweRecipient';
import IJweBase from './IJweBase';
import { TSMap } from 'typescript-map'

/**
 * Defines a header in JWE
 */
export type JweHeader = TSMap<string, string>;

/**
 * JWE general json format
 */
export default interface IJweGeneralJson extends IJweBase {

  /**
   * The recipients that can decrypt
   */
  recipients: IJweRecipient[]
}
