/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { PublicKey } from 'verifiablecredentials-crypto-sdk-typescript-keys';

export default interface IJsonLinkedDataProofSuite {
    /**
     * The type of the suite
     */
    type: string[];

    /**
     * Sign the payload
     * @param payload Payload to be signed
     */
    sign(payload: object): Promise<IJsonLinkedDataProofSuite>;

    /**
     * Validate the signature on a credential
     * @param validationKeys Public keys used to validate the signature
     */
    verify(validationKeys?: PublicKey[]): Promise<boolean>;


    /**
    * Serialize a the payload
    */
    serialize(): Promise<string>;

    /**
     * Deserialize a credential
     * @param credential The credential to deserialize.
     */
    deserialize(credential: string): Promise<IJsonLinkedDataProofSuite>;
}