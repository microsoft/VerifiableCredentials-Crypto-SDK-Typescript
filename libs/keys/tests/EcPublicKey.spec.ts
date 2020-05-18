import { EcPublicKey, KeyType } from '../lib';
import base64url from 'base64url';

describe('EcPublicKey', () =>{
    it('should create an EC public key', () => {
        let key: any = {
            kty: KeyType.EC,
            crv: 'secp256k1',
            x: 'AQAB',
            y: 'AQAB',
            alg: 'secp256k1'
        };

        let ecPublicKey = new EcPublicKey(key);
        expect(ecPublicKey.alg).toEqual('secp256k1');
        
        key = {
            kty: KeyType.EC,
            crv: 'secp256k1',
            alg: 'ecdsa'
        };

        key.x = base64url.toBuffer('AQAB');
        key.y = base64url.toBuffer('AQAB');
        ecPublicKey = new EcPublicKey(key);
        expect(ecPublicKey.kty).toEqual(KeyType.EC);
        
        key = {
            kty: KeyType.OKP,
            crv: 'ed25519',
            alg: 'eddsa'
        };

        key.x = base64url.toBuffer('AQAB');
        delete key.y;
        ecPublicKey = new EcPublicKey(key);
        expect(ecPublicKey.kty).toEqual(KeyType.OKP);
    });
});