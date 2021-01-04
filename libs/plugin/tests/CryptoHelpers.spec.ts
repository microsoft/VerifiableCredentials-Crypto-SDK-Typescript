import { SubtleCryptoNode, CryptoFactory, CryptoFactoryScope, CryptoHelpers } from '../lib/index';
import { KeyStoreInMemory, KeyReference } from 'verifiablecredentials-crypto-sdk-typescript-keystore';

describe('CryptoHelpers', () => {
    it('should return getSubtleCryptoForAlgorithm', () => {
        const keyStore = new KeyStoreInMemory();
        let factory = new CryptoFactory(keyStore, SubtleCryptoNode.getSubtleCrypto());
        let keyReference = new KeyReference('', 'secret');
        let subtle = CryptoHelpers.getSubtleCryptoForAlgorithm(factory, {name: 'RSASSA-PKCS1-V1_5'}, CryptoFactoryScope.All, keyReference);
        expect(subtle.constructor.name).toEqual('Subtle');
        subtle = CryptoHelpers.getSubtleCryptoForAlgorithm(factory, {name: 'ECDSA'}, CryptoFactoryScope.All, keyReference);
        expect(subtle.constructor.name).toEqual('Subtle');
        subtle = CryptoHelpers.getSubtleCryptoForAlgorithm(factory, {name: 'EdDSA'}, CryptoFactoryScope.All, keyReference);
        expect(subtle.constructor.name).toEqual('Subtle');
        subtle = CryptoHelpers.getSubtleCryptoForAlgorithm(factory, {name: 'RSA-OAEP'}, CryptoFactoryScope.All, keyReference);
        expect(subtle.constructor.name).toEqual('Subtle');
        subtle = CryptoHelpers.getSubtleCryptoForAlgorithm(factory, {name: 'RSA-OAEP-256'}, CryptoFactoryScope.All, keyReference);
        expect(subtle.constructor.name).toEqual('Subtle');
        subtle = CryptoHelpers.getSubtleCryptoForAlgorithm(factory, {name: 'AES-GCM'}, CryptoFactoryScope.All, keyReference);
        expect(subtle.constructor.name).toEqual('Subtle');
        subtle = CryptoHelpers.getSubtleCryptoForAlgorithm(factory, {name: 'HMAC'}, CryptoFactoryScope.All, keyReference);
        expect(subtle.constructor.name).toEqual('Subtle');
        subtle = CryptoHelpers.getSubtleCryptoForAlgorithm(factory, {name: 'SHA-256'}, CryptoFactoryScope.All, keyReference);
        expect(subtle.constructor.name).toEqual('Subtle');
        subtle = CryptoHelpers.getSubtleCryptoForAlgorithm(factory, {name: 'SHA-384'}, CryptoFactoryScope.All, keyReference);
        expect(subtle.constructor.name).toEqual('Subtle');
        subtle = CryptoHelpers.getSubtleCryptoForAlgorithm(factory, {name: 'SHA-512'}, CryptoFactoryScope.All, keyReference);
        expect(subtle.constructor.name).toEqual('Subtle');

        // Negative cases
        expect(() => CryptoHelpers.getSubtleCryptoForAlgorithm(factory, {name: 'SHA1'}, CryptoFactoryScope.All, keyReference)).toThrowError(`Algorithm '{"name":"SHA1"}' is not supported`);
          
        const testSpy = { name: 'SHA-1' };
        const webCryptoToJwaSpy: jasmine.Spy = spyOn(CryptoHelpers, 'webCryptoToJwa').and.callFake(() => 'SHA-1');
        expect(() => CryptoHelpers.getSubtleCryptoForAlgorithm(factory, <any>testSpy, CryptoFactoryScope.All, keyReference)).toThrowError(`Algorithm '{"name":"SHA-1"}' is not supported. Should be unreachable`);
    });
    it('should return jwaToWebCrypto', () => {
        expect(CryptoHelpers.jwaToWebCrypto('Rs256')).toEqual({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: { name: 'SHA-256'} });
        expect(CryptoHelpers.jwaToWebCrypto('Rs384')).toEqual({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: { name: 'SHA-384'} });
        expect(CryptoHelpers.jwaToWebCrypto('Rs512')).toEqual({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: { name: 'SHA-512'} });
        expect(CryptoHelpers.jwaToWebCrypto('RSA-OAEP-256')).toEqual({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: 'SHA-256' });
        expect(CryptoHelpers.jwaToWebCrypto('RSA-OAEP')).toEqual({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: 'SHA-256' });
        expect(CryptoHelpers.jwaToWebCrypto('A128GCM', [0,1,2], [3,4,5])).toEqual({ name: 'AES-GCM', iv: [0, 1, 2], additionalData: [3,4,5], tagLength: 128, length: 128});
        expect(CryptoHelpers.jwaToWebCrypto('A192GCM', [0,1,2], [3,4,5])).toEqual({ name: 'AES-GCM', iv: [0, 1, 2], additionalData: [3,4,5], tagLength: 128, length: 192});
        expect(CryptoHelpers.jwaToWebCrypto('A256GCM', [0,1,2], [3,4,5])).toEqual({ name: 'AES-GCM', iv: [0, 1, 2], additionalData: [3,4,5], tagLength: 128, length: 256});
        expect(CryptoHelpers.jwaToWebCrypto('Es256k')).toEqual({ name: 'ECDSA', namedCurve: 'secp256k1', crv: 'secp256k1', hash: { name: 'SHA-256' } });
        expect(CryptoHelpers.jwaToWebCrypto('EdDSA')).toEqual({ name: 'EdDSA', namedCurve: 'ed25519', crv: 'ed25519', hash: { name: 'SHA-256' } });
        expect(CryptoHelpers.jwaToWebCrypto('SHA-256')).toEqual({ hash: { name: 'SHA-256'} });
        expect(CryptoHelpers.jwaToWebCrypto('SHA-384')).toEqual({ hash: { name: 'SHA-384'} });
        expect(CryptoHelpers.jwaToWebCrypto('SHA-512')).toEqual({ hash: { name: 'SHA-512'} });
        expect(CryptoHelpers.jwaToWebCrypto('HS256')).toEqual({ name: 'HMAC', hash: { name: 'SHA-256'} });
        expect(CryptoHelpers.jwaToWebCrypto('HS384')).toEqual({ name: 'HMAC', hash: { name: 'SHA-384'} });
        expect(CryptoHelpers.jwaToWebCrypto('HS512')).toEqual({ name: 'HMAC', hash: { name: 'SHA-512'} });

        // Negative cases
        expect(() => CryptoHelpers.jwaToWebCrypto('SHA1')).toThrowError(`Algorithm 'SHA1' is not supported`);
    });
    
    it('should return webCryptoToJwa', () => {
        expect(CryptoHelpers.webCryptoToJwa({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: { name: 'SHA-256'} })).toEqual('RS256');
        expect(CryptoHelpers.webCryptoToJwa({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: { name: 'SHA-384'} })).toEqual('RS384');
        expect(CryptoHelpers.webCryptoToJwa({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: { name: 'SHA-512'} })).toEqual('RS512');
        expect(CryptoHelpers.webCryptoToJwa({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: 'SHA-256' })).toEqual('RSA-OAEP-256');
        expect(CryptoHelpers.webCryptoToJwa({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: 'SHA-256' })).toEqual('RSA-OAEP-256');
        expect(CryptoHelpers.webCryptoToJwa({ name: 'AES-GCM', iv: [0, 1, 2], additionalData: [3,4,5], tagLength: 128, length: 128})).toEqual('A128GCM');
        expect(CryptoHelpers.webCryptoToJwa({ name: 'AES-GCM', iv: [0, 1, 2], additionalData: [3,4,5], tagLength: 128, length: 192})).toEqual('A192GCM');
        expect(CryptoHelpers.webCryptoToJwa({ name: 'AES-GCM', iv: [0, 1, 2], additionalData: [3,4,5], tagLength: 128, length: 256})).toEqual('A256GCM');
        expect(CryptoHelpers.webCryptoToJwa({ name: 'ECDSA', namedCurve: 'secp256k1', crv: 'secp256k1', hash: { name: 'SHA-256' } })).toEqual('ES256K');
        expect(CryptoHelpers.webCryptoToJwa({ name: 'EdDSA', namedCurve: 'ed25519', crv: 'ed25519', hash: { name: 'SHA-256' } })).toEqual('EdDSA');
        expect(CryptoHelpers.webCryptoToJwa({ name: 'SHA-256' })).toEqual('SHA-256');
        expect(CryptoHelpers.webCryptoToJwa({ name: 'SHA-384' })).toEqual('SHA-384');
        expect(CryptoHelpers.webCryptoToJwa({ name: 'SHA-512' })).toEqual('SHA-512');
        expect(CryptoHelpers.webCryptoToJwa({ name: 'HMAC', hash: { name: 'SHA-256'} })).toEqual('HS256');

        // Negative cases
        expect(() => CryptoHelpers.webCryptoToJwa({ name: 'SHA1' })).toThrowError(`Algorithm '{"name":"SHA1"}' is not supported`);
    });
    
    it('should return getKeyImportAlgorithm', () => {
        let jwk: any = {crv: 'secp256k1'};
        expect(CryptoHelpers.getKeyImportAlgorithm(<any>{ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: { name: 'SHA-256'} }, jwk)).toEqual(<any>{ name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256'} });
        expect(CryptoHelpers.getKeyImportAlgorithm(<any>{ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: { name: 'SHA-384'} }, jwk)).toEqual(<any>{ name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-384'} });
        expect(CryptoHelpers.getKeyImportAlgorithm(<any>{ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: { name: 'SHA-512'} }, jwk)).toEqual(<any>{ name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-512'} });
        expect(CryptoHelpers.getKeyImportAlgorithm(<any>{ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: 'SHA-256' }, jwk)).toEqual(<any>{ name: 'RSA-OAEP', hash: 'SHA-256' });
        expect(CryptoHelpers.getKeyImportAlgorithm(<any>{ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: 'SHA-256' }, jwk)).toEqual(<any>{ name: 'RSA-OAEP', hash: 'SHA-256' });
        expect(CryptoHelpers.getKeyImportAlgorithm(<any>{ name: 'ECDSA', namedCurve: 'secp256k1', crv: 'secp256k1', hash: { name: 'SHA-256' } }, jwk)).toEqual(<any>{ name: 'ECDSA', namedCurve: 'secp256k1', hash: { name: 'SHA-256' } });
        jwk = {crv: 'ed25519'};
        expect(CryptoHelpers.getKeyImportAlgorithm(<any>{ name: 'EdDSA', namedCurve: 'ed25519', crv: 'ed25519', hash: { name: 'SHA-256' } }, jwk)).toEqual(<any>{ name: 'EdDSA', namedCurve: 'ed25519', hash: { name: 'SHA-256' } });
        expect(CryptoHelpers.getKeyImportAlgorithm(<any>{ name: 'SHA-256' }, jwk)).toEqual(<any>{ name: 'SHA-256', hash: 'SHA-256' });
        expect(CryptoHelpers.getKeyImportAlgorithm(<any>{ name: 'SHA-384' }, jwk)).toEqual(<any>{ name: 'SHA-384', hash: 'SHA-384' });
        expect(CryptoHelpers.getKeyImportAlgorithm(<any>{ name: 'SHA-512' }, jwk)).toEqual(<any>{ name: 'SHA-512', hash: 'SHA-512' });
        expect(CryptoHelpers.getKeyImportAlgorithm(<any>{ name: 'HMAC', hash: { name: 'SHA-256'} }, jwk)).toEqual(<any>{ name: 'HMAC', hash: { name: 'SHA-256'} });
        expect(CryptoHelpers.getKeyImportAlgorithm(<any>{ name: 'AES-GCM'}, jwk)).toEqual(<any>{ name: 'AES-GCM' });
       
        // Negative cases
        expect(() => CryptoHelpers.getKeyImportAlgorithm(<any>{ name: 'SHA-1'}, jwk)).toThrowError(`Algorithm '{"name":"SHA-1"}' is not supported`);
    });
});