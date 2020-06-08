/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { IPayloadProtectionSigning, IPayloadProtectionEncrypting } from './index';


/**
 * Genereric type to model crypto tokens for protocols
 */
export interface IProtocolCryptoToken {
  
  /**
   * Gets the protocol
   */
  protocol(): IPayloadProtectionSigning | IPayloadProtectionEncrypting;

  /**
   * Serialize a @interface IProtocolCryptoToken 
   */
  serialize(): string;
}
