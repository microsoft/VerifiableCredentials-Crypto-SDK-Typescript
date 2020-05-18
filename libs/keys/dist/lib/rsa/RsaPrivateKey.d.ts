import RsaPublicKey from './RsaPublicKey';
import PrivateKey from '../PrivateKey';
import PublicKey from '../PublicKey';
/**
 * Represents an Elliptic Curve private key
 * @class
 * @extends PrivateKey
 */
export default class RsaPrivateKey extends RsaPublicKey implements PrivateKey {
    /**
     * Private exponent
     */
    d: string;
    /**
     * Prime p
     */
    p: string;
    /**
     * Prime q
     */
    q: string;
    /**
     * Private dp
     */
    dp: string;
    /**
     * Private dq
     */
    dq: string;
    /**
     * Private qi
     */
    qi: string;
    /**
     * Create instance of @class RsaPrivateKey
     */
    constructor(key: any);
    /**
     * Gets the corresponding public key
     * @returns The corresponding {@link PublicKey}
     */
    getPublicKey(): PublicKey;
}
