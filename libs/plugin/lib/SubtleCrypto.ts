import { CryptoFactory } from './index';
import { CryptoKeyPair, CryptoKey } from 'webcrypto-core';
import { CryptoFactoryScope } from './CryptoFactory';
const { Crypto } = require("@peculiar/webcrypto");

/**
 * Wrapper class for subtle crypto
 */
export default class SubtleCrypto {
    constructor() {
      console.log(`SubtleCrypto object created`);
    }

    private subtle = new Crypto().subtle;
    private _cryptoFactory: CryptoFactory | undefined;

    public set  cryptoFactory(cryptoFactory: CryptoFactory | undefined) {
        this._cryptoFactory = cryptoFactory;
    }

    public get  cryptoFactory(): CryptoFactory | undefined {
        return this._cryptoFactory;
    }

    public async digest(algorithm: Algorithm, data: BufferSource): Promise<ArrayBuffer> {
      // CryptoFactory transforms
      algorithm = this.cryptoFactory ? this.cryptoFactory.algorithmTransform(algorithm) : algorithm;

      const result = await this.subtle.digest(algorithm, data);

      return result;
  }


    public async generateKey(algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair | CryptoKey> {
        // CryptoFactory transforms
        algorithm = this.cryptoFactory ? this.cryptoFactory.algorithmTransform(algorithm) : algorithm;

        const result = await this.subtle.generateKey(algorithm, extractable, keyUsages);
        return result;
    }

    public async sign(algorithm: Algorithm, key: CryptoKey, data: BufferSource): Promise<ArrayBuffer> {
        // CryptoFactory transforms
        algorithm = this.cryptoFactory ? this.cryptoFactory.algorithmTransform(algorithm) : algorithm;

        const result = await this.subtle.sign(algorithm, key, data);

        return result;
    }

    public async verify(algorithm: Algorithm, key: CryptoKey, signature: BufferSource, data: BufferSource): Promise<boolean> {
        // CryptoFactory transforms
        algorithm = this.cryptoFactory ? this.cryptoFactory.algorithmTransform(algorithm) : algorithm;

        const result = await this.subtle.verify(algorithm, key, signature, data);

        return result;
    }

    public async encrypt(algorithm: Algorithm, key: CryptoKey, data: BufferSource): Promise<ArrayBuffer> {
        // CryptoFactory transforms
        algorithm = this.cryptoFactory ? this.cryptoFactory.algorithmTransform(algorithm) : algorithm;

        const result = await this.subtle.encrypt(algorithm, key, data);

        return result;
    }

    public async decrypt(algorithm: Algorithm, key: CryptoKey, data: BufferSource): Promise<ArrayBuffer> {
        // CryptoFactory transforms
        algorithm = this.cryptoFactory ? this.cryptoFactory.algorithmTransform(algorithm) : algorithm;

        const result = await this.subtle.decrypt(algorithm, key, data);

        return result;
    }

    public async deriveBits(algorithm: Algorithm, baseKey: CryptoKey, length: number): Promise<ArrayBuffer> {
        // CryptoFactory transforms
        algorithm = this.cryptoFactory ? this.cryptoFactory.algorithmTransform(algorithm) : algorithm;

        const result = await this.subtle.deriveBits(algorithm, baseKey, length);

        return result;
    }

    public async deriveKey(algorithm: Algorithm, baseKey: CryptoKey, derivedKeyType: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
        // CryptoFactory transforms
        algorithm = this.cryptoFactory ? this.cryptoFactory.algorithmTransform(algorithm) : algorithm;

        const result = await this.subtle.deriveBits(algorithm, baseKey, derivedKeyType, extractable, keyUsages);

        return result;
    }

    //public async exportKey(format: "raw" | "spki" | "pkcs8", key: CryptoKey): Promise<ArrayBuffer>;
    //public async exportKey(format: "jwk", key: CryptoKey): Promise<JsonWebKey>;
    //public async exportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer>;
    public async exportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
        // CryptoFactory transforms

        let result = await this.subtle.exportKey(format, key);
        result = this.cryptoFactory ? this.cryptoFactory.keyTransform(result, CryptoFactoryScope.All) : result;
        return result;
    }

    public async importKey(format: KeyFormat, keyData: JsonWebKey | BufferSource, algorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
        // CryptoFactory transforms
      algorithm = this.cryptoFactory ? this.cryptoFactory.algorithmTransform(algorithm) : algorithm;

        const result = await this.subtle.importKey(format, keyData, algorithm, extractable, keyUsages);

        return result;
    }

    public async wrapKey(format: KeyFormat, key: CryptoKey, wrappingKey: CryptoKey, wrapAlgorithm: Algorithm): Promise<ArrayBuffer> {
        const result = await this.subtle.wrapKey(format, key, wrappingKey, wrapAlgorithm);
        return result;
    }

    public async unwrapKey(format: KeyFormat, wrappedKey: BufferSource, unwrappingKey: CryptoKey, unwrapAlgorithm: Algorithm, unwrappedKeyAlgorithm: Algorithm, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
        const result = await this.subtle.unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages);
        return result;
    }

}