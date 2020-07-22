import { EcPrivateKey, KeyType } from '../lib';
import base64url from 'base64url';

describe('EcPrivateKey', () =>{
    it('should create an EC key', () => {
        const key = {
            kty: KeyType.EC,
            d: 'AQAB',
            x: 'AQAB',
            y: 'AQAB',
            alg: 'ES256K',
            crv: 'secp256k1'
        };

        let ecPrivateKey = new EcPrivateKey(key);
        expect(ecPrivateKey.alg).toEqual('ES256K');
        expect(ecPrivateKey.crv).toEqual('secp256k1');
        expect((<any>ecPrivateKey.getPublicKey()).d).toBeUndefined();
        expect((<any>ecPrivateKey.getPublicKey()).x).toEqual('AQAB');

        (<any>key).d = base64url.toBuffer('AQAB');
        ecPrivateKey = new EcPrivateKey(key);
        expect(ecPrivateKey.alg).toEqual('ES256K');
    });
});