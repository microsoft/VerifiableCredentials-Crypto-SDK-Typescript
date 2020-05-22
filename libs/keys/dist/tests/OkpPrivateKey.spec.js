"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const lib_1 = require("../lib");
describe('OkpPrivateKey', () => {
    it('should create an OPK key', () => {
        const key = {
            kty: lib_1.KeyType.EC,
            d: 'AQAB',
            x: 'AQAB',
            alg: 'EdDSA'
        };
        let okpPrivateKey = new lib_1.OkpPrivateKey(key);
        expect(okpPrivateKey.alg).toEqual('EdDSA');
        expect(okpPrivateKey.getPublicKey().d).toBeUndefined();
        expect(okpPrivateKey.getPublicKey().x).toEqual('AQAB');
    });
});
//# sourceMappingURL=OkpPrivateKey.spec.js.map