import { OkpPublicKey, KeyType } from '../lib';
import base64url from 'base64url';

describe('OkpPublicKey', () =>{
    it('should create an OKP public key', () => {
        let key: any = {
            kty: KeyType.OKP,
            crv: 'ed25519',
            x: 'AQAB',
            alg: 'EdDSA'
        };

        let okpPublicKey = new OkpPublicKey(key);
        expect(okpPublicKey.alg).toEqual('EdDSA');
        
        key = {
            kty: KeyType.OKP,
            crv: 'ed25519',
            alg: 'EdDSA'
        };

        key.x = base64url.toBuffer('AQAB');
        key.y = base64url.toBuffer('AQAB');
        okpPublicKey = new OkpPublicKey(key);
        expect(okpPublicKey.kty).toEqual(KeyType.OKP);
        
        key = {
            kty: KeyType.OKP,
            crv: 'ed25519',
            alg: 'EdDSA'
        };

        key.x = base64url.toBuffer('AQAB');
        delete key.y;
        okpPublicKey = new OkpPublicKey(key);
        expect(okpPublicKey.kty).toEqual(KeyType.OKP);
    });
});