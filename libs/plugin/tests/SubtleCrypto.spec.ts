import { SubtleCrypto, CryptoFactory, SubtleCryptoNode } from '../lib';
import { KeyStoreInMemory } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import { verify } from 'crypto';
import base64url from 'base64url';

// Samples are based on  https://github.com/diafygi/webcrypto-examples
describe('SubtleCrypto', () => {
    const subtle = new SubtleCrypto();

    const genKey = async () => {
        const cryptoKey = await subtle.generateKey(
            <HmacKeyGenParams>{
                name: "HMAC",
                hash: { name: "SHA-256" }, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
                //length: 256, //optional, if you want your key length to differ from the hash function's block length
            },
            true, //whether the key is extractable (i.e. can be used in exportKey)
            ["sign", "verify"] //can be any combination of "sign" and "verify"
        );
        return cryptoKey;
    }

    const random = async (byteLen: number) => {
        const cryptoKey = await genKey();
        const jwk: any = await subtle.exportKey(
            'jwk', //can be "jwk" or "raw"
            <CryptoKey>cryptoKey);   //extractable must be true
        const ran = base64url.toBuffer(jwk.k);
        return ran.slice(0, byteLen);
    }

    it('should create SubtleCrypto', () => {
        const subtle = new SubtleCrypto();
        expect(subtle.constructor.name).toEqual('SubtleCrypto');
    });

    it('should generate key', async () => {
        const cryptoKey = await genKey();
        expect(cryptoKey).toBeDefined();
    });

    it('should import/export key', async () => {
        const cryptoKey = await genKey();
        const jwk: any = await subtle.exportKey(
            'jwk', //can be "jwk" or "raw"
            <CryptoKey>cryptoKey);   //extractable must be true
        expect(jwk.k).toBeDefined();

        subtle.importKey(
            "jwk", //can be "jwk" or "raw"
            jwk,
            <HmacImportParams>{   //this is the algorithm options
                name: "HMAC",
                hash: { name: "SHA-256" }, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
                //length: 256, //optional, if you want your key length to differ from the hash function's block length
            },
            true, //whether the key is extractable (i.e. can be used in exportKey)
            ["sign", "verify"] //can be any combination of "sign" and "verify"
        )
    });

    it('should sign/verify', async () => {
        const cryptoKey = await genKey();
        const payload = `Jules, did you ever hear the philosophy that once a man admits that he's wrong that he is immediately forgiven for all wrongdoings? Have you ever heard that?`;
        const signature = await subtle.sign(
            {
                name: 'HMAC',
            },
            <CryptoKey>cryptoKey, //from generateKey or importKey above
            Buffer.from(payload)); //ArrayBuffer of data you want to sign
        const valid = await subtle.verify(
            {
                name: 'HMAC',
            },
            <CryptoKey>cryptoKey, //from generateKey or importKey above
            signature, //ArrayBuffer of the signature
            Buffer.from(payload)); //ArrayBuffer of the data
        expect(valid).toBeTruthy();
    });

    it('should digest', async () => {
        const payload = `If my answers frighten you then you should cease asking scary questions.`;
        const hash = await subtle.digest(
            {
                name: 'SHA-256',
            },
            Buffer.from(payload)); //The data you want to hash as an ArrayBuffer
        expect(hash.byteLength === 32).toBeTruthy();
    });


    it('should encrypt/decrypt', async () => {
        const cryptoKey = await subtle.generateKey(
            <AesKeyGenParams>{
                name: "AES-GCM",
                length: 256, //can be  128, 192, or 256
            },
            true, //whether the key is extractable (i.e. can be used in exportKey)
            ["encrypt", "decrypt"]); //can "encrypt", "decrypt", "wrapKey", or "unwrapKey"

        const payload = `That's a pretty ... good milkshake. I don't know if it's worth five dollars but it's pretty ... good.`;
        const aad = 'authenticate me';
        const iv = await random(12);
        const cipher = await subtle.encrypt(
            <AesGcmParams>{
                name: "AES-GCM",

                //Don't re-use initialization vectors!
                //Always generate a new iv every time your encrypt!
                //Recommended to use 12 bytes length
                iv: iv,

                //Additional authentication data (optional)
                additionalData: Buffer.from(aad),

                //Tag length (optional)
                tagLength: 128, //can be 32, 64, 96, 104, 112, 120 or 128 (default)
            },
            <CryptoKey>cryptoKey, //from generateKey or importKey above
            Buffer.from(payload)); //ArrayBuffer of data you want to encrypt

        const result = await subtle.decrypt(
            <AesGcmParams>{
                name: "AES-GCM",
                iv: iv, //The initialization vector you used to encrypt
                additionalData: Buffer.from(aad), //The addtionalData you used to encrypt (if any)
                tagLength: 128, //The tagLength you used to encrypt (if any)
            },
            <CryptoKey>cryptoKey, //from generateKey or importKey above
            cipher //ArrayBuffer of the data
        )
        expect(Buffer.from(result).toString()).toEqual(payload);
    });
});