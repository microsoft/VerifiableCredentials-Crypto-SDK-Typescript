/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { PublicKey } from 'verifiablecredentials-crypto-sdk-typescript-keys';

export default interface IJsonLinkedDataProofSuite {
    /**
     * The type of the suite
     */
    type: string;

    /**
     * Gets the algorithm for the suite
     */
    alg: string;

    /**
     * Sign the payload
     * @param payload Payload to be signed
     */
    sign(payload: object): Promise<any>;

    /**
     * Validate the signature on a credential
     * @param validationKeys Public keys used to validate the signature
     * @param signedPayload Optional. The payload to verify
     */
    verify(validationKeys?: PublicKey[], signedPayload?: any): Promise<boolean>;


    /**
    * Serialize a the payload
    */
    serialize(signedPayload?: any): string;

    /**
     * Deserialize a credential
     * @param credential The credential to deserialize.
     */
    deserialize(credential: string): any;
}