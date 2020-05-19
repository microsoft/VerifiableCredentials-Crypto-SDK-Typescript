import { SubtleCrypto } from '../lib/index';
import { ISubtleCrypto } from '../lib/ISubtleCryptoExtension';

/**
 * Subtle crypto for node
 *  */
 export default class SubtleCryptoMock  extends SubtleCrypto {
  public ID = 'SubtleCryptoMock';
}
