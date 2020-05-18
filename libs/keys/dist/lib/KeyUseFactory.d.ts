/**
 * Enumeration to model key use.
 */
export declare enum KeyUse {
    Encryption = "enc",
    Signature = "sig"
}
/**
 * Factory class to create @enum KeyUse objects.
 */
export default class KeyUseFactory {
    /**
     * Create the key use according to the selected algorithm.
     * @param algorithm Web crypto compliant algorithm object
     */
    static createViaWebCrypto(algorithm: any): KeyUse;
    /**
     * Create the key use according to the selected JWA algorithm.
     * @param alg JWA name
     */
    static createViaJwa(alg: string): KeyUse;
}
