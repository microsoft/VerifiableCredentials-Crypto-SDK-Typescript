import { SubtleCrypto } from './index';
import { ISubtleCrypto } from './ISubtleCryptoExtension';

/**
 * Subtle crypto for node
 *  */
 export default class SubtleCryptoNode implements ISubtleCrypto {
  private static crypto: SubtleCrypto = new SubtleCrypto();

/**
 * Returns the @class SubtleCrypto implementation for the nodes environment
 */
 public getSubtleCrypto(): any {
  return SubtleCryptoNode.getSubtleCrypto();
}   

/**
 * Returns the @class SubtleCrypto implementation for the nodes environment
 */
  public static getSubtleCrypto(): any {
    return SubtleCryptoNode.crypto;
  }   
}
