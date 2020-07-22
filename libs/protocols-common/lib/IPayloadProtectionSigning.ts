/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import IPayloadProtectionOptions from './IPayloadProtectionOptions';
import { PublicKey } from 'verifiablecredentials-crypto-sdk-typescript-keys';
import IVerificationResult from './IVerificationResult';
import { IProtocolCryptoToken } from './IProtocolCryptoToken';

/**
 * Interface defining the implementation of the selected protocol for signing.
 */
export interface IPayloadProtectionSigning {
  
  /**
   * Signs contents using the given private key reference.
   *
   * @param payload to sign.
   * @returns Signed payload in requested format.
   */
  sign(payload: Buffer | object): Promise<IPayloadProtectionSigning>;

  /**
   * Verify the signature.
   *
   * @param validationKeys Public key to validate the signature.
   * @returns True if signature validated.
   */
  verify(validationKeys?: PublicKey[]): Promise<boolean>;

  /**
   * Serialize a cryptographic token
   */
  serialize(): string;

  /**
   * Deserialize a cryptographic token
   * @param token The crypto token to serialize.
   */
  deserialize(token: string): IPayloadProtectionSigning;
}
