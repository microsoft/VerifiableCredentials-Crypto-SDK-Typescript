"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const lib_1 = require("../lib");
const base64url_1 = require("base64url");
describe('EcPublicKey', () => {
    it('should create an EC public key', () => {
        let key = {
            kty: lib_1.KeyType.EC,
            crv: 'secp256k1',
            x: 'AQAB',
            y: 'AQAB',
            alg: 'secp256k1'
        };
        let ecPublicKey = new lib_1.EcPublicKey(key);
        expect(ecPublicKey.alg).toEqual('secp256k1');
        key = {
            kty: lib_1.KeyType.EC,
            crv: 'secp256k1',
            alg: 'ecdsa'
        };
        key.x = base64url_1.default.toBuffer('AQAB');
        key.y = base64url_1.default.toBuffer('AQAB');
        ecPublicKey = new lib_1.EcPublicKey(key);
        expect(ecPublicKey.kty).toEqual(lib_1.KeyType.EC);
        key = {
            kty: lib_1.KeyType.OKP,
            crv: 'ed25519',
            alg: 'eddsa'
        };
        key.x = base64url_1.default.toBuffer('AQAB');
        delete key.y;
        ecPublicKey = new lib_1.EcPublicKey(key);
        expect(ecPublicKey.kty).toEqual(lib_1.KeyType.OKP);
    });
});
//# sourceMappingURL=EcPublicKey.spec.js.map