/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

 import {  CryptoKey } from 'webcrypto-core';
import { SubtleCrypto } from 'webcrypto-core';
import { KeyReference } from 'verifiablecredentials-crypto-sdk-typescript-keystore';

const { Crypto } = require("@peculiar/webcrypto");
const clone = require('clone');

// Named curves
const CURVE_P256K = 'P-256K';
const CURVE_K256 = 'K-256';
const CURVE_SECP256K1 = 'SECP256K1';

export interface IKeyGenerationOptions {
    /**
     * Specify the reference of the key
     */
    keyReference?: KeyReference,

    /**
     * Specify the curve for the key to generate
     */
    curve?: string
}

/**
 * Wrapper class for W3C subtle crypto.
 * A subtle crypto class is the actual crypto library to be used.
 */
export default class Subtle extends SubtleCrypto {
   
    private subtle: SubtleCrypto = new Crypto().subtle;

    constructor() {
        super();
    }

    /**
     * Normalize the algorithm so it can be used by underlying crypto.
     * @param algorithm Algorithm to be normalized
     */
    public algorithmTransform(algorithm: any) {
        if (algorithm.namedCurve) {
            const curve = (<string>algorithm.namedCurve).toUpperCase();
            if (curve === CURVE_P256K || curve === CURVE_SECP256K1) {
                const alg = clone(algorithm);
                alg.namedCurve = CURVE_K256;
                algorithm = alg;
            }
        }

        if (algorithm.crv) {
            const curve = (<string>algorithm.crv).toUpperCase();
            if (curve === CURVE_P256K || curve === CURVE_SECP256K1) {
                const alg = clone(algorithm);
                alg.crv = CURVE_K256;
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
            const curve = (<string>jwk.crv).toUpperCase();
            if (curve === CURVE_P256K || curve === CURVE_SECP256K1) {
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
            const curve = (<string>jwk.crv).toUpperCase();
            if (curve === CURVE_P256K || curve === CURVE_K256) {
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


    public async generateKey(algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[], _options?: IKeyGenerationOptions): Promise<CryptoKeyPair | CryptoKey> {
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

    public async exportKey(format: "raw" | "spki" | "pkcs8", key: CryptoKey): Promise<ArrayBuffer>;
    public async exportKey(format: "jwk", key: CryptoKey): Promise<JsonWebKey>;
    public async exportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {

        let result = await this.subtle.exportKey(format, key);
        result = format === 'jwk' ? this.keyExportTransform(result): result;

        return result;
    }

    public async importKey(format: KeyFormat, keyData: JsonWebKey | BufferSource, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
        algorithm = this.algorithmTransform(algorithm);
        keyData = format === 'jwk' ? this.keyImportTransform(keyData): keyData;
        const key: CryptoKey = await this.subtle.importKey(format, keyData, algorithm, extractable, keyUsages);
        return key;
    }
}