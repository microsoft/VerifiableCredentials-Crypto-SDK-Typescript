"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const lib_1 = require("../lib");
describe('OkpPrivateKey', () => {
    it('should create an OPK key', () => {
        const key = {
            kty: lib_1.KeyType.EC,
            d: 'AQAB',
            x: 'AQAB',
            alg: 'ed25519'
        };
        let okpPrivateKey = new lib_1.OkpPrivateKey(key);
        expect(okpPrivateKey.alg).toEqual('ed25519');
        expect(okpPrivateKey.getPublicKey().d).toEqual('AQAB');
        expect(okpPrivateKey.getPublicKey().x).toEqual('AQAB');
    });
});
//# sourceMappingURL=OkpPrivateKey.spec.js.map