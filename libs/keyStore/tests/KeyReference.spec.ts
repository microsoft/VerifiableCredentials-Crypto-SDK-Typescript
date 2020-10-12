import { KeyReference } from '../lib';
import { CryptoKey } from 'webcrypto-core';

describe('KeyReference', () =>{
    it('should create a KeyReference', () =>{
        let reference = new KeyReference('key');
        expect(reference.type).toEqual('secret');
        expect(reference.keyReference).toEqual('key');
        expect(reference.cryptoKey).toBeUndefined();
        expect(reference.remoteKeyReference).toBeUndefined();

        reference = new KeyReference('key', 'secret');
        expect(reference.type).toEqual('secret');
        expect(reference.keyReference).toEqual('key');
        expect(reference.cryptoKey).toBeUndefined();
        expect(reference.remoteKeyReference).toBeUndefined();
        
        reference = new KeyReference('key', 'secret', 'remote');
        expect(reference.type).toEqual('secret');
        expect(reference.keyReference).toEqual('key');
        expect(reference.remoteKeyReference).toEqual('remote');
        expect(reference.cryptoKey).toBeUndefined();
        
        reference = new KeyReference('key', 'secret', 'remote', new CryptoKey());
        expect(reference.type).toEqual('secret');
        expect(reference.keyReference).toEqual('key');
        expect(reference.remoteKeyReference).toEqual('remote');
        expect(reference.cryptoKey).toBeDefined();
    });
});