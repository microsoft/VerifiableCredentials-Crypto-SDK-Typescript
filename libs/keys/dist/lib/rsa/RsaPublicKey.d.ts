import { KeyType } from '../KeyTypeFactory';
import JsonWebKey from '../JsonWebKey';
/**
 * Represents an RSA public key
 * @class
 * @extends PublicKey
 */
export default class RsaPublicKey extends JsonWebKey {
    /**
     * Public exponent
     */
    e: string;
    /**
     * Modulus
     */
    n: string;
    /**
     * Set the EC key type
     */
    kty: KeyType;
    /**
     * Set the default algorithm
     */
    alg: string;
    /**
     * Create instance of @class RsaPublicKey
     */
    constructor(key: any);
}
