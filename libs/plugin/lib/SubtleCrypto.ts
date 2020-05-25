import { CryptoFactory } from './index';
import { CryptoKeyPair, CryptoKey } from 'webcrypto-core';
import { CryptoFactoryScope } from './CryptoFactory';
const { Crypto } = require("@peculiar/webcrypto");
const clone = require('clone');

// Named curves
const CURVE_P256K = 'P-256K';
const CURVE_K256 = 'K-256';
const CURVE_SECP256K1 = 'secp256k1';


/**
 * Wrapper class for W3C subtle crypto.
 * A subtle crypto class is the actual crypto library to be used.
 */
export default class SubtleCrypto {
   
    private subtle = new Crypto().subtle;

    constructor() {
    }

    /**
     * Normalize the algorithm so it can be used by underlying crypto.
     * @param algorithm Algorithm to be normalized
     */
    public algorithmTransform(algorithm: any) {
        if (algorithm.namedCurve) {
            if (algorithm.namedCurve === CURVE_P256K || algorithm.namedCurve === CURVE_SECP256K1) {
                const alg = clone(algorithm);
                alg.namedCurve = CURVE_K256;
                return alg;
            }
        }

        return algorithm;
    }

    /**
   * Normalize the JWK parameters so it can be used by underlying crypto.
   * @param jwk Json web key to be normalized
   */
    public keyImportTransform(jwk: any) {
        if (jwk.crv) {
            if (jwk.crv === CURVE_P256K || jwk.crv === CURVE_SECP256K1) {
                const clonedKey = clone(jwk);
                clonedKey.crv = CURVE_K256;
                return clonedKey;
            }
        }

        return jwk;
    }

    /**
     * Normalize the JWK parameters from the underlying crypto so it is normalized to standardized parameters.
     * @param jwk Json web key to be normalized
     */
    public keyExportTransform(jwk: any) {
        if (jwk.crv) {
            if (jwk.crv === CURVE_P256K || jwk.crv === CURVE_K256) {
                const clonedKey = clone(jwk);
                clonedKey.crv = CURVE_SECP256K1;
                return clonedKey;
            }
        }

        return jwk;
    }

    public async digest(algorithm: Algorithm, data: BufferSource): Promise<ArrayBuffer> {
        algorithm = this.algorithmTransform(algorithm);
        const result = await this.subtle.digest(algorithm, data);

        return result;
    }


    public async generateKey(algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[], _options?: any): Promise<CryptoKeyPair | CryptoKey> {
        algorithm = this.algorithmTransform(algorithm);
        const result = await this.subtle.generateKey(algorithm, extractable, keyUsages);

        return result;
    }

    public async sign(algorithm: Algorithm, key: CryptoKey, data: BufferSource): Promise<ArrayBuffer> {
        algorithm = this.algorithmTransform(algorithm);
        const result = await this.subtle.sign(algorithm, key, data);

        return result;
    }

    public async verify(algorithm: Algorithm, key: CryptoKey, signature: BufferSource, data: BufferSource): Promise<boolean> {
        algorithm = this.algorithmTransform(algorithm);
        const result = await this.subtle.verify(algorithm, key, signature, data);

        return result;
    }

    public async encrypt(algorithm: Algorithm, key: CryptoKey, data: BufferSource): Promise<ArrayBuffer> {
        algorithm = this.algorithmTransform(algorithm);
        const result = await this.subtle.encrypt(algorithm, key, data);

        return result;
    }

    public async decrypt(algorithm: Algorithm, key: CryptoKey, data: BufferSource): Promise<ArrayBuffer> {
        algorithm = this.algorithmTransform(algorithm);
        const result = await this.subtle.decrypt(algorithm, key, data);

        return result;
    }

    //public async exportKey(format: "raw" | "spki" | "pkcs8", key: CryptoKey): Promise<ArrayBuffer>;
    //public async exportKey(format: "jwk", key: CryptoKey): Promise<JsonWebKey>;
    //public async exportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer>;
    public async exportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {

        let result = await this.subtle.exportKey(format, key);
        result = format === 'jwk' ? this.keyExportTransform(result): result;

        return result;
    }

    public async importKey(format: KeyFormat, keyData: JsonWebKey | BufferSource, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
        algorithm = this.algorithmTransform(algorithm);
        keyData = format === 'jwk' ? this.keyImportTransform(keyData): keyData;
        const result = await this.subtle.importKey(format, keyData, algorithm, extractable, keyUsages);

        return result;
    }
}