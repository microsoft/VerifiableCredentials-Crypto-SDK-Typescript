import { KeyType } from './KeyTypeFactory';
import { KeyUse } from './KeyUseFactory';
/**
 * JWK key operations
 */
export declare enum KeyOperation {
    Sign = "sign",
    Verify = "verify",
    Encrypt = "encrypt",
    Decrypt = "decrypt",
    WrapKey = "wrapKey",
    UnwrapKey = "unwrapKey",
    DeriveKey = "deriveKey",
    DeriveBits = "deriveBits"
}
/**
 * Represents a Public Key in JWK format.
 * @class
 * @abstract
 * @hideconstructor
 */
export default abstract class JsonWebKey {
    /**
     * Key type
     */
    kty: KeyType;
    /**
     * Key ID
     */
    kid?: string;
    /**
     * Intended use
     */
    use?: KeyUse;
    /**
     * Valid key operations (key_ops)
     */
    key_ops?: KeyOperation[];
    /**
     * Algorithm intended for use with this key
     */
    alg?: string;
    /**
     * Create instance of @class JsonWebKey
     */
    constructor(key: JsonWebKey);
}
