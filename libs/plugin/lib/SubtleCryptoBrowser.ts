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
 * Returns the @class Subtle implementation for the browser environment
 */
 public getSubtleCrypto(): any {
  return SubtleCryptoBrowser.getSubtleCrypto();
 }   

   /**
    * Returns the @class Subtle implementation for the current environment
    */
   public static getSubtleCrypto(): SubtleCrypto {
    // tslint:disable-next-line:no-typeof-undefined
    if (typeof window !== 'undefined') {
     // return browser api
     return <SubtleCrypto>(window.crypto?.subtle);
    }
    
    throw new CryptoError(<any>{}, 'window is not defined. Must be defined in browser.')  
  }

  /**
   * Normalize the algorithm so it can be used by underlying crypto.
   * @param algorithm Algorithm to be normalized
   */
  public algorithmTransform(algorithm: any) {
    return algorithm;
  }

  /**
 * Normalize the JWK parameters so it can be used by underlying crypto.
 * @param jwk Json web key to be normalized
 */
  public keyImportTransform(jwk: any) {
    return jwk;
  }

  /**
   * Normalize the JWK parameters from the underlying crypto so it is normalized to standardized parameters.
   * @param jwk Json web key to be normalized
   */
  public keyExportTransform(jwk: any) {
    return jwk;
  }
 }
