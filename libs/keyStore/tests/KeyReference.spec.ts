import { KeyReference } from '../lib';
import { CryptoKey } from 'webcrypto-core';

describe('KeyReference', () =>{
    it('should create a KeyReference', () =>{
        let reference = new KeyReference('key');
        expect(reference.type).toEqual('key');
        expect(reference.keyReference).toEqual('key');
        expect(reference.cryptoKey).toBeUndefined();

        reference = new KeyReference('key', 'secret');
        expect(reference.type).toEqual('secret');
        expect(reference.keyReference).toEqual('key');
        expect(reference.cryptoKey).toBeUndefined();

        reference = new KeyReference('key', 'secret', new CryptoKey());
        expect(reference.type).toEqual('secret');
        expect(reference.keyReference).toEqual('key');
        expect(reference.cryptoKey).toBeDefined();
    });
});