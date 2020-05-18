"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const lib_1 = require("../lib");
const base64url_1 = require("base64url");
describe('EcPrivateKey', () => {
    it('should create an EC key', () => {
        const key = {
            kty: lib_1.KeyType.EC,
            d: 'AQAB',
            x: 'AQAB',
            y: 'AQAB',
            alg: 'secp256k1'
        };
        let ecPrivateKey = new lib_1.EcPrivateKey(key);
        expect(ecPrivateKey.alg).toEqual('secp256k1');
        expect(ecPrivateKey.getPublicKey().d).toBeUndefined();
        expect(ecPrivateKey.getPublicKey().x).toEqual('AQAB');
        key.d = base64url_1.default.toBuffer('AQAB');
        ecPrivateKey = new lib_1.EcPrivateKey(key);
        expect(ecPrivateKey.alg).toEqual('secp256k1');
    });
});
//# sourceMappingURL=EcPrivateKey.spec.js.map