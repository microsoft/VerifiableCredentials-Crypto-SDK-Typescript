import EcPublicKey from './EcPublicKey';
import PrivateKey from '../PrivateKey';
import PublicKey from '../PublicKey';
/**
 * Represents an Elliptic Curve private key
 * @class
 * @extends PrivateKey
 */
export default class OkpPrivateKey extends EcPublicKey implements PrivateKey {
    /**
     * EdDSA w/ ed25519 Curve
     */
    readonly alg: string;
    /**
     * Private exponent
     */
    d: string;
    /**
     * Create instance of @class EcPrivateKey
     */
    constructor(key: any);
    /**
     * Gets the corresponding public key
     * @returns The corresponding {@link PublicKey}
     */
    getPublicKey(): PublicKey;
}
