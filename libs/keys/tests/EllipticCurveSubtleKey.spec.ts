import { EllipticCurveSubtleKey, KeyType } from '../lib';

describe('EllipticCurveSubtleKey', () =>{
    it('should create an EC subtle key', () => {
        const key = {
            kty: KeyType.EC,
            d: 'AQAB',
            x: 'AQAB',
            y: 'AQAB',
            alg: 'secp256k1'
        };

        let ellipticCurveSubtleKey = new EllipticCurveSubtleKey(
            { name: "ECDSA" },
            false,
            ["sign", "verify"],
            'private',
            key);
        expect(ellipticCurveSubtleKey.algorithm).toEqual({ name: "ECDSA" });
    });
});