import { OkpPrivateKey, KeyType } from '../lib';

describe('OkpPrivateKey', () =>{
    it('should create an OPK key', () => {
        const key = {
            kty: KeyType.EC,
            crv: 'ed25519',
            d: 'AQAD',
            x: 'AQAB',
            alg: 'EdDSA'
        };

        let okpPrivateKey = new OkpPrivateKey(key);
        expect(okpPrivateKey.alg).toEqual('EdDSA');
        expect((<any>okpPrivateKey.getPublicKey()).d).toBeUndefined();
        expect((<any>okpPrivateKey.getPublicKey()).x).toEqual('AQAB');
        expect(<any>okpPrivateKey.alg).toEqual('EdDSA');
        expect(<any>okpPrivateKey.d).toEqual('AQAD');
    });
});