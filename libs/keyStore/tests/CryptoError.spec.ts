import { CryptoError } from '../lib';

describe('CryptoError', () =>{
    it('should create a CryptoError', () =>{
        const error = new CryptoError({name: 'ECDSA'}, 'error occured');
        expect(error.algorithm).toEqual({name: 'ECDSA'});
        expect(error.message).toEqual('error occured');
    });
});