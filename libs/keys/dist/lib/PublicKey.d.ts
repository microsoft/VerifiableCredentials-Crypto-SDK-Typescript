import JsonWebKey from './JsonWebKey';
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
export default abstract class PublicKey extends JsonWebKey {
    /**
     * Obtains the thumbprint for the jwk parameter
     * @param jwk JSON object representation of a JWK
     */
    static getThumbprint(publicKey: PublicKey): Promise<string>;
}
