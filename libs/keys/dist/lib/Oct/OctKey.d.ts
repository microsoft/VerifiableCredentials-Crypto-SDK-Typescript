import { KeyType } from '../KeyTypeFactory';
import JsonWebKey from '../JsonWebKey';
import SecretKey from '../SecretKey';
/**
 * Represents an OCT key
 * @class
 * @extends JsonWebKey
 */
export default class OctKey extends JsonWebKey implements SecretKey {
    /**
     * secret
     */
    k: string;
    /**
     * Set the Oct key type
     */
    kty: KeyType;
    /**
     * Create instance of @class EcPublicKey
     */
    constructor(key: string);
}
