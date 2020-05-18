/**
 * Enumeration to model key types.
 */
export declare enum KeyType {
    Oct = "oct",
    EC = "EC",
    RSA = "RSA",
    OKP = "OKP"
}
/**
 * Factory class to create @enum KeyType objects
 */
export default class KeyTypeFactory {
    /**
     * Create the key type according to the selected algorithm.
     * @param algorithm Web crypto compliant algorithm object
     */
    static createViaWebCrypto(algorithm: any): KeyType;
    /**
     * Create the key type according to the selected JWA algorithm.
     * @param alg JWA name
     */
    static createViaJwa(alg: string): KeyType;
}
