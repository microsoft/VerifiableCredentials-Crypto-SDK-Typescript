import { KeyReferenceOptions } from '../lib';

describe('KeyReferenceOptions', () =>{
    it('should create a KeyReferenceOptions', () =>{
        let reference = new KeyReferenceOptions({extractable: true, keyReference: 'key'});
        expect(reference.extractable).toBeTruthy();
        expect(reference.keyReference).toEqual('key');

        reference = new KeyReferenceOptions({keyReference: 'key'});
        expect(reference.extractable).toBeTruthy();
        expect(reference.keyReference).toEqual('key');

        reference = new KeyReferenceOptions({extractable: false, keyReference: 'key'});
        expect(reference.extractable).toBeFalsy();
        expect(reference.keyReference).toEqual('key');
    });
});