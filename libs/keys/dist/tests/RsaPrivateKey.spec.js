"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const lib_1 = require("../lib");
const base64url_1 = require("base64url");
describe('RsaPrivateKey', () => {
    fit('should create an RSA key', () => {
        const key = {
            kty: lib_1.KeyType.RSA,
            d: 'AQAB',
            n: 'AQAB',
            e: 'AQAB',
            dp: 'AQAB',
            dq: 'AQAB',
            p: 'AQAB',
            q: 'AQAB',
            qi: 'AQAB',
            alg: 'rsa'
        };
        let rsaPrivateKey = new lib_1.RsaPrivateKey(key);
        expect(rsaPrivateKey.alg).toEqual('rsa');
        expect(rsaPrivateKey.getPublicKey().d).toBeUndefined();
        expect(rsaPrivateKey.getPublicKey().n).toEqual('AQAB');
        key.d = base64url_1.default.toBuffer('AQAB');
        key.n = base64url_1.default.toBuffer('AQAB');
        key.e = base64url_1.default.toBuffer('AQAB');
        key.dp = base64url_1.default.toBuffer('AQAB');
        key.dq = base64url_1.default.toBuffer('AQAB');
        key.p = base64url_1.default.toBuffer('AQAB');
        key.q = base64url_1.default.toBuffer('AQAB');
        key.qi = base64url_1.default.toBuffer('AQAB');
        rsaPrivateKey = new lib_1.RsaPrivateKey(key);
        expect(rsaPrivateKey.alg).toEqual('rsa');
        expect(rsaPrivateKey.getPublicKey().d).toBeUndefined();
        expect(rsaPrivateKey.getPublicKey().n).toEqual('AQAB');
    });
});
//# sourceMappingURL=RsaPrivateKey.spec.js.map