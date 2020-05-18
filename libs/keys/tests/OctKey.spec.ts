import { OctKey, KeyType } from '../lib';

describe('OctKey', () =>{
    it('should create an oct key', () => {
        const octKey = new OctKey('AQAB');
        expect(octKey.kty).toEqual(KeyType.Oct);
    });
});