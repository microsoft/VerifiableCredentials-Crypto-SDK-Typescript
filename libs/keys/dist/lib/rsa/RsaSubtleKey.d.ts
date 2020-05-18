import { CryptoKey } from 'webcrypto-core';
/**
 * Implementation of the CryptoKey for RSA
 * based keys.
 */
export default class RsaSubtleKey extends CryptoKey {
    /**
     *
     * Gets the specification of the algorithm
     */
    algorithm: KeyAlgorithm;
    /**
     * Key type
     */
    type: KeyType;
    /**
     * Different usages supported by the provider
     */
    usages: KeyUsage[];
    /**
     * True if key is exportable
     */
    extractable: boolean;
    /**
     * The elliptic curve key
     */
    key: any;
    /**
     * Create an instance of RsaSubtleKey
     * @param algorithm for the key
     * @param extractable True if key can be extracted
     * @param usages for the key
     * @param type of the key (private || public)
     * @param key to be used
     */
    constructor(algorithm: KeyAlgorithm, extractable: boolean, usages: KeyUsage[], type: KeyType, key: any);
}
