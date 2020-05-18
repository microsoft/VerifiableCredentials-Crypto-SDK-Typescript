import { CryptoKey } from 'webcrypto-core';
/**
 * Implementation of the CryptoKey for elliptic curve
 * based keys.
  */
export default class EllipticCurveKey extends CryptoKey {
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
     * Create an instance of EcCryptoKey
     * @param algorithm for the key
     * @param extractable True if key can be extracted
     * @param usages for the key
     * @param type of the key (private || public)
     * @param key to be used
     */
    constructor(algorithm: KeyAlgorithm, extractable: boolean, usages: KeyUsage[], type: KeyType, key: any);
}
