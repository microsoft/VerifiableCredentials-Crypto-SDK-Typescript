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
}
