"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const lib_1 = require("../lib");
describe('EllipticCurveSubtleKey', () => {
    it('should create an EC subtle key', () => {
        const key = {
            kty: lib_1.KeyType.EC,
            d: 'AQAB',
            x: 'AQAB',
            y: 'AQAB',
            alg: 'secp256k1'
        };
        let ellipticCurveSubtleKey = new lib_1.EllipticCurveSubtleKey({ name: "ECDSA" }, false, ["sign", "verify"], 'private', key);
        expect(ellipticCurveSubtleKey.algorithm).toEqual({ name: "ECDSA" });
    });
});
//# sourceMappingURL=EllipticCurveSubtleKey.spec.js.map