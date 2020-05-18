"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const lib_1 = require("../lib");
describe('OctKey', () => {
    it('should create an oct key', () => {
        const octKey = new lib_1.OctKey('AQAB');
        expect(octKey.kty).toEqual(lib_1.KeyType.Oct);
    });
});
//# sourceMappingURL=OctKey.spec.js.map