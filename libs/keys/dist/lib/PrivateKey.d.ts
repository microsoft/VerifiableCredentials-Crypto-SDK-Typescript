import PublicKey from './PublicKey';
import JsonWebKey from './JsonWebKey';
/**
 * Represents a Private Key in JWK format.
 * @class
 * @abstract
 * @hideconstructor
 */
export default abstract class PrivateKey extends JsonWebKey {
    /**
     * Gets the corresponding public key
     * @returns The corresponding {@link PublicKey}
     */
    abstract getPublicKey(): PublicKey;
}
