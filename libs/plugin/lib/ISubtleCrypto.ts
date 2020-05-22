/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { SubtleCrypto } from './index';


/**
 * Interface for the Subtle Crypto 
 */
 export default interface ISubtleCrypto {
 
/**
 * Returns the @class SubtleCrypto implementation for the nodes environment
 */
 getSubtleCrypto(): SubtleCrypto;
}