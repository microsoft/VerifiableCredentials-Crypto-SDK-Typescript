import { RsaSubtleKey, KeyType } from '../lib';

describe('RsaSubtleKey', () =>{
    it('should create an RSA subtle key', () => {
        const key = {
            kty: KeyType.RSA,
            e: 'AQAB',
            n: 'AQAB',
            alg: 'rsa'
        };

        let rsaSubtleKey = new RsaSubtleKey(
            { name: "RSA-OAEP" },
            false,
            ["decrypt", "encrypt"],
            'public',
            key);
        expect(rsaSubtleKey.algorithm).toEqual({ name: "RSA-OAEP" });
    });
});