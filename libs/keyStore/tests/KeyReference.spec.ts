import { KeyReference } from '../lib';
import { CryptoKey } from 'webcrypto-core';

describe('KeyReference', () =>{
    it('should create a KeyReference', () =>{
        let reference = new KeyReference('key');
        expect(reference.extractable).toBeTruthy();
        expect(reference.keyReference).toEqual('key');
        expect(reference.cryptoKey).toBeUndefined();

        reference = new KeyReference('key', false);
        expect(reference.extractable).toBeFalsy();
        expect(reference.keyReference).toEqual('key');
        expect(reference.cryptoKey).toBeUndefined();

        reference = new KeyReference('key', false, new CryptoKey());
        expect(reference.extractable).toBeFalsy();
        expect(reference.keyReference).toEqual('key');
        expect(reference.cryptoKey).toBeDefined();
    });
});