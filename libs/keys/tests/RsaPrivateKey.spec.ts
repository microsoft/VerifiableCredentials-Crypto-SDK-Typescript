import { RsaPrivateKey, KeyType } from '../lib';
import base64url from 'base64url';

describe('RsaPrivateKey', () =>{
    it('should create an RSA key', () => {
        const key: any = {
            kty: KeyType.RSA,
            d: 'AQAB',
            n: 'AQAB',
            e: 'AQAB',
            dp: 'AQAB',
            dq: 'AQAB',
            p: 'AQAB',
            q: 'AQAB',
            qi: 'AQAB',
            alg: 'rsa'
        };

        let rsaPrivateKey = new RsaPrivateKey(key);
        expect(rsaPrivateKey.alg).toEqual('rsa');
        expect((<any>rsaPrivateKey.getPublicKey()).d).toBeUndefined();
        expect((<any>rsaPrivateKey.getPublicKey()).n).toEqual('AQAB');

        key.d = base64url.toBuffer('AQAB');
        key.n = base64url.toBuffer('AQAB');
        key.e = base64url.toBuffer('AQAB');
        key.dp = base64url.toBuffer('AQAB');
        key.dq = base64url.toBuffer('AQAB');
        key.p = base64url.toBuffer('AQAB');
        key.q = base64url.toBuffer('AQAB');
        key.qi = base64url.toBuffer('AQAB');
        rsaPrivateKey = new RsaPrivateKey(key);
        expect(rsaPrivateKey.alg).toEqual('rsa');
        expect((<any>rsaPrivateKey.getPublicKey()).d).toBeUndefined();
        expect((<any>rsaPrivateKey.getPublicKey()).n).toEqual('AQAB');
    });
});