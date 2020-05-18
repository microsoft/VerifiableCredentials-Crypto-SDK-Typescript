/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Enumeration to model key use.
 */
export enum KeyUse {
  Encryption = 'enc',
  Signature = 'sig'
}

/**
 * Factory class to create @enum KeyUse objects.
 */
export default class KeyUseFactory {
  /**
   * Create the key use according to the selected algorithm.
   * @param algorithm Web crypto compliant algorithm object
   */
  public static createViaWebCrypto (algorithm: any): KeyUse {
    switch (algorithm.name.toLowerCase()) {
      case 'hmac':
        return KeyUse.Signature;

      case 'ecdsa':
        return KeyUse.Signature;

      case 'eddsa':
        return KeyUse.Signature;

      case 'ecdh':
        return KeyUse.Encryption;

      case 'rsassa-pkcs1-v1_5':
        return KeyUse.Signature;

      case 'rsa-oaep':
      case 'rsa-oaep-256':
        return KeyUse.Encryption;

      default:
        throw new Error(`The algorithm '${algorithm.name}' is not supported`);
    }
  }

  /**
   * Create the key use according to the selected JWA algorithm.
   * @param alg JWA name
   */
   public static createViaJwa (alg: string): KeyUse {
    switch (alg.toLowerCase()) {
      case 'rs256':
      case 'rs384':
      case 'rs512':
      case 'es256k':
      case 'secp256k1':
      case 'ecdsa':
      case 'eddsa':
        return KeyUse.Signature;
      case 'rsa-oaep':
      case 'rsa-oaep-256':
      case 'a128gcm':
      case 'a256gcm':
      case 'a192gcm':
        return KeyUse.Encryption;
    }

    throw new Error(`Algorithm '${alg}' is not supported`);
  }
}
