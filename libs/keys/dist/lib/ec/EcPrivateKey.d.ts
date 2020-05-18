import EcPublicKey from './EcPublicKey';
import PrivateKey from '../PrivateKey';
import PublicKey from '../PublicKey';
/**
 * Represents an Elliptic Curve private key
 * @class
 * @extends PrivateKey
 */
export default class EcPrivateKey extends EcPublicKey implements PrivateKey {
    /**
     * ECDSA w/ secp256k1 Curve
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
