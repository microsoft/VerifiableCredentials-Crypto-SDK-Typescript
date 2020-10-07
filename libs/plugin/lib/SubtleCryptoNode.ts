import { Subtle, ISubtleCrypto } from './index';

/**
 * Subtle crypto for node
 *  */
 export default class SubtleCryptoNode implements ISubtleCrypto {
  private static crypto: Subtle = new Subtle();

/**
 * Returns the @class Subtle implementation for the nodes environment
 */
 public getSubtleCrypto(): any {
  return SubtleCryptoNode.getSubtleCrypto();
}   

/**
 * Returns the @class Subtle implementation for the nodes environment
 */
  public static getSubtleCrypto(): any {
    return SubtleCryptoNode.crypto;
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
