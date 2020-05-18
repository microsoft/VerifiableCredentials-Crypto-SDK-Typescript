/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Enumeration to model key types.
 */
export enum KeyType {
  Oct = 'oct',
  EC = 'EC',
  RSA = 'RSA',
  OKP = 'OKP'
}

/**
 * Factory class to create @enum KeyType objects
 */
export default class KeyTypeFactory {
  /**
   * Create the key type according to the selected algorithm.
   * @param algorithm Web crypto compliant algorithm object
   */
  public static createViaWebCrypto (algorithm: any): KeyType {
    switch (algorithm.name.toLowerCase()) {
      case 'hmac':
        return KeyType.Oct;

      case 'ecdsa':
        return KeyType.EC;

      case 'eddsa':
        return KeyType.OKP;

      case 'ecdh':
        return KeyType.EC;

      case 'rsassa-pkcs1-v1_5':
        return KeyType.RSA;

      case 'rsa-oaep':
      case 'rsa-oaep-256':
        return KeyType.RSA;

      default:
        throw new Error(`The algorithm '${algorithm.name}' is not supported`);
    }
  }

  /**
   * Create the key type according to the selected JWA algorithm.
   * @param alg JWA name
   */
  public static createViaJwa (alg: string): KeyType {
    switch (alg.toLowerCase()) {
      case 'rs256':
      case 'rs384':
      case 'rs512':
      case 'rsa-oaep':
      case 'rsa-oaep-256':
        return KeyType.RSA;
      case 'a128gcm':
      case 'a256gcm':
      case 'a192gcm':
       return KeyType.Oct;
      case 'es256k':
      case 'secp256k1':
      case 'ecdsa':
      case 'eddsa':
       return KeyType.EC;
    }

    throw new Error(`Algorithm '${alg}' is not supported`);
  }
}
