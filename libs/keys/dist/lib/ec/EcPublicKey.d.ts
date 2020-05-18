import JsonWebKey from '../JsonWebKey';
import PublicKey from '../PublicKey';
/**
 * Represents an Elliptic Curve public key
 * @class
 * @extends PublicKey
 */
export default class EcPublicKey extends JsonWebKey implements PublicKey {
    /**
     * curve
     */
    crv: string | undefined;
    /**
     * x co-ordinate
     */
    x: string;
    /**
     * y co-ordinate
     */
    y: string;
    /**
     * Create instance of @class EcPublicKey
     */
    constructor(key: EcPublicKey);
}
