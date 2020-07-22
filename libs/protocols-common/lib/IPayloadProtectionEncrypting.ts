/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

 import IPayloadProtectionOptions from './IPayloadProtectionOptions';
 import { PublicKey } from 'verifiablecredentials-crypto-sdk-typescript-keys';
 import { KeyReference } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import IVerificationResult from './IVerificationResult';
import { ICryptoToken } from './ICryptoToken';

/**
 * Interface defining the implementation of the selected protocol for encryption.
 */
export interface IPayloadProtectionEncrypting {

  /**
   * Encrypt content using the given public keys in JWK format.
   * The key type enforces the key encryption algorithm.
   * The options can override certain algorithm choices.
   * 
   * @param recipients List of recipients' public keys.
   * @param payload to encrypt.
   * @param format of the final serialization.
   * @param options used for the signature. These options override the options provided in the constructor.
   * @returns JweToken with encrypted payload.
   */
   encrypt (recipients: PublicKey[], payload: Buffer, format: string, options?: IPayloadProtectionOptions): Promise<ICryptoToken>;

  /**
   * Decrypt the content.
   * 
   * @param decryptionKeyReference Reference to the decryption key.
   * @param token The crypto token to decrypt.
   * @param options used for the decryption. These options override the options provided in the constructor.
   * @returns Decrypted payload.
   */
   decrypt (decryptionKeyReference: string, cipher: ICryptoToken, options?: IPayloadProtectionOptions): Promise<Buffer>;
}
