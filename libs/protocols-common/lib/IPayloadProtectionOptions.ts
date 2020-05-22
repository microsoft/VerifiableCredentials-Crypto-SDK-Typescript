/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { CryptoFactory } from 'verifiablecredentials-crypto-sdk-typescript-plugin';
import { IPayloadProtection } from './IPayloadProtection';
import { TSMap } from "typescript-map";

/**
 * Interface defining options for the selected protocol.
 */
export default interface IPayloadProtectionOptions {
 // The crypto algorithm suites used for cryptography
 cryptoFactory: CryptoFactory,

 // The implementation of the selected protocol
 payloadProtection: IPayloadProtection,

 // A dictionary for protocol specific options
 options: TSMap<string, any>
}
