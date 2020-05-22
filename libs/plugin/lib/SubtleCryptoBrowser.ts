/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { CryptoError } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import { ISubtleCrypto } from './index';
 
 /**
  * Subtle crypto for browser
  **/
 export default class SubtleCryptoBrowser implements ISubtleCrypto {
 /**
 * Returns the @class SubtleCrypto implementation for the browser environment
 */
 public getSubtleCrypto(): any {
  return SubtleCryptoBrowser.getSubtleCrypto();
 }   

   /**
    * Returns the @class SubtleCrypto implementation for the current environment
    */
   public static getSubtleCrypto(): SubtleCrypto {
    // tslint:disable-next-line:no-typeof-undefined
    if (typeof window !== 'undefined') {
     // return browser api
     return <SubtleCrypto>window.crypto.subtle;
    }
    
    throw new CryptoError(<any>{}, 'window is not defined. Must be defined in browser.')  
  }
 }
