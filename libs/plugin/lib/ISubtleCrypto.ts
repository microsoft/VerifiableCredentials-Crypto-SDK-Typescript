/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { SubtleCrypto } from 'webcrypto-core';

/**
export class SubtleCryptoBase extends Subtle {
  public checkRequiredArguments(args: IArguments, size: number, methodName: string) {
      // ignore size from core implementation and use additional argument
      console.log(`checkRequiredArguments ${methodName}`);

      switch (methodName) {
        case "generateKey":
          return super.checkRequiredArguments(args, 4, methodName); // +1 extra argument
        default:
          return super.checkRequiredArguments(args, size, methodName)
      }
    }
}
**/

/**
 * Interface for the Subtle Crypto 
 */
 export default interface ISubtleCrypto {
 
/**
 * Returns the @class SubtleCryptoBase implementation for the nodes environment
 */
 getSubtleCrypto(): SubtleCrypto;
}
