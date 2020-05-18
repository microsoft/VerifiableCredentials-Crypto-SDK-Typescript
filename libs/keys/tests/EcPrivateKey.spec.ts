import { EcPrivateKey, KeyType } from '../lib';
import base64url from 'base64url';

describe('EcPrivateKey', () =>{
    it('should create an EC key', () => {
        const key = {
            kty: KeyType.EC,
            d: 'AQAB',
            x: 'AQAB',
            y: 'AQAB',
            alg: 'secp256k1'
        };

        let ecPrivateKey = new EcPrivateKey(key);
        expect(ecPrivateKey.alg).toEqual('secp256k1');
        expect((<any>ecPrivateKey.getPublicKey()).d).toBeUndefined();
        expect((<any>ecPrivateKey.getPublicKey()).x).toEqual('AQAB');

        (<any>key).d = base64url.toBuffer('AQAB');
        ecPrivateKey = new EcPrivateKey(key);
        expect(ecPrivateKey.alg).toEqual('secp256k1');
    });
});