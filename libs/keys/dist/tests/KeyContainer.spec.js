"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
const index_1 = require("../lib/index");
describe('KeyContainer', () => {
    it('should create a KeyContainer', () => {
        const key = {
            kty: index_1.KeyType.RSA,
            use: index_1.KeyUse.Signature,
            kid: 'signing',
            n: 'abcdefg',
            e: 'AQAB',
            alg: 'rsa'
        };
        const container = new index_1.KeyContainer(key);
        expect(container.getKey().kty).toEqual(index_1.KeyType.RSA);
        expect(container.kty).toEqual(index_1.KeyType.RSA);
        expect(container.getKey().use).toEqual(index_1.KeyUse.Signature);
        expect(container.use).toEqual(index_1.KeyUse.Signature);
        expect(container.getKey().kid).toEqual(key.kid);
        expect(container.getKey().alg).toEqual(key.alg);
        expect(container.alg).toEqual(key.alg);
        expect(container.getKey().n).toEqual(key.n);
        expect(container.getKey().e).toEqual(key.e);
        expect(container.remotekey()).toBeFalsy();
        key.kid = 'https://example.com';
        container.add(key);
        expect(container.keys.length === 2);
        expect(container.remotekey()).toBeTruthy();
        // Negative cases
        // Add key with wrong type
        const ecKey = {
            kty: index_1.KeyType.EC,
            use: index_1.KeyUse.Signature,
            kid: 'signing'
        };
        expect(() => container.add(ecKey)).toThrow(new Error(`Cannot add a key with kty 'EC' to a key container with kty 'RSA'`));
        // Add key with wrong use
        ecKey.kty = index_1.KeyType.RSA;
        ecKey.use = index_1.KeyUse.Encryption;
        expect(() => container.add(ecKey)).toThrow(new Error(`Cannot add a key with use 'enc' to a key container with use 'sig'`));
        // empty container
        container.keys = [];
        expect(container.remotekey()).toBeFalsy();
    });
});
//# sourceMappingURL=KeyContainer.spec.js.map