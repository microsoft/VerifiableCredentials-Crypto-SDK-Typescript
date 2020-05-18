/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { KeyContainer, RsaPublicKey, KeyType, KeyUse, KeyOperation, JsonWebKey, PublicKey } from "../lib/index";

 describe('KeyContainer', () => {
     it ('should create a KeyContainer', () => {
        const key: RsaPublicKey = {
            kty: KeyType.RSA,
            use: KeyUse.Signature,
            kid: 'signing',
            n: 'abcdefg',
            e: 'AQAB',
            alg: 'rsa'
        };
        const container = new KeyContainer(key);
        expect(container.getKey().kty).toEqual(KeyType.RSA);
        expect(container.kty).toEqual(KeyType.RSA);
        expect(container.getKey().use).toEqual(KeyUse.Signature);
        expect(container.use).toEqual(KeyUse.Signature);
        expect(container.getKey().kid).toEqual(key.kid);
        expect(container.getKey().alg).toEqual(key.alg);
        expect(container.alg).toEqual(key.alg);
        expect((<RsaPublicKey>container.getKey()).n).toEqual(key.n);
        expect((<RsaPublicKey>container.getKey()).e).toEqual(key.e);
        expect(container.remotekey()).toBeFalsy();
        key.kid = 'https://example.com';
        container.add(key);
        expect(container.keys.length === 2);
        expect(container.remotekey()).toBeTruthy();
            
        // Negative cases
        // Add key with wrong type
        const ecKey = {
            kty: KeyType.EC,
            use: KeyUse.Signature,
            kid: 'signing'
        };
        expect(()=>container.add(ecKey)).toThrow(new Error(`Cannot add a key with kty 'EC' to a key container with kty 'RSA'`));
        
        // Add key with wrong use
        ecKey.kty = KeyType.RSA;
        ecKey.use = KeyUse.Encryption;
        expect(()=>container.add(ecKey)).toThrow(new Error(`Cannot add a key with use 'enc' to a key container with use 'sig'`));
    
        // empty container
        container.keys = [];
        expect(container.remotekey()).toBeFalsy();
     });
 });
