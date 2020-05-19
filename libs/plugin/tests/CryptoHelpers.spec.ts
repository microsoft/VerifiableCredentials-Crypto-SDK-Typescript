import { CryptoHelpers, CryptoFactoryNode, SubtleCryptoNode, CryptoFactoryScope, SubtleCrypto } from '../lib';
import { KeyStoreInMemory } from '@microsoft/crypto-keystore';
import { W3cCryptoApiConstants } from '@microsoft/crypto-keys';

describe('CryptoHelpers', () => {
    const keyStore = new KeyStoreInMemory();
    const factory = new CryptoFactoryNode(keyStore, SubtleCryptoNode.getSubtleCrypto());

    it(`should return the subtle for W3C 'eddsa'`, () => {
        const alg = {name: 'eddsa'};
        expect(CryptoHelpers.getSubtleCryptoForAlgorithm(factory, alg, CryptoFactoryScope.All).constructor.name).toEqual('SubtleCryptoElliptic');
      });

      it(`should return the subtle for W3C 'ECDSA'`, () => {
        const alg = {name: 'ECDSA'};
        expect(CryptoHelpers.getSubtleCryptoForAlgorithm(factory, alg, CryptoFactoryScope.All).constructor.name).toEqual('SubtleCrypto');
      });

      it(`should return the subtle for W3C 'RSASSA-PKCS1-V1_5'`, () => {
        const alg = {name: 'RSASSA-PKCS1-V1_5'};
        console.log(CryptoHelpers.getSubtleCryptoForAlgorithm(factory, alg, CryptoFactoryScope.All).constructor.name);
        expect(CryptoHelpers.getSubtleCryptoForAlgorithm(factory, alg, CryptoFactoryScope.All).constructor.name).toEqual('SubtleCrypto');
      });

      it(`should return the subtle for W3C 'RSA-OAEP'`, () => {
        const alg = {name: 'RSA-OAEP'};
        expect(CryptoHelpers.getSubtleCryptoForAlgorithm(factory, alg, CryptoFactoryScope.All).constructor.name).toEqual('SubtleCrypto');
      });

      it(`should return the subtle for W3C 'RSA-OAEP-256'`, () => {
        const alg = {name: 'RSA-OAEP-256'};
        expect(CryptoHelpers.getSubtleCryptoForAlgorithm(factory, alg, CryptoFactoryScope.All).constructor.name).toEqual('SubtleCrypto');
      });

      it(`should return the subtle for W3C 'AES-GCM'`, () => {
        const alg = {name: 'AES-GCM'};
        expect(CryptoHelpers.getSubtleCryptoForAlgorithm(factory, alg, CryptoFactoryScope.All).constructor.name).toEqual('SubtleCrypto');
      });

      it(`should return the subtle for W3C 'HMAC'`, () => {
        const alg = {name: 'HMAC'};
        expect(CryptoHelpers.getSubtleCryptoForAlgorithm(factory, alg, CryptoFactoryScope.All).constructor.name).toEqual('SubtleCrypto');
      });
      
      it(`should return the subtle for W3C 'SHA-256'`, () => {
        const alg = {name: 'SHA-256'};
        expect(CryptoHelpers.getSubtleCryptoForAlgorithm(factory, alg, CryptoFactoryScope.All).constructor.name).toEqual('SubtleCrypto');
      });
      
      it(`should return the subtle for W3C 'SHA-384'`, () => {
        const alg = {name: 'SHA-384'};
        expect(CryptoHelpers.getSubtleCryptoForAlgorithm(factory, alg, CryptoFactoryScope.All).constructor.name).toEqual('SubtleCrypto');
      });
      
      it(`should return the subtle for W3C 'SHA-512'`, () => {
        const alg = {name: 'SHA-512'};
        expect(CryptoHelpers.getSubtleCryptoForAlgorithm(factory, alg, CryptoFactoryScope.All).constructor.name).toEqual('SubtleCrypto');
      });
      
      it(`should return W3C for JWA 'RSASSA-PKCS1-V1_5'`, () => {
        const alg = {name: 'RSASSA-PKCS1-V1_5', hash:'sha-384'};
        expect(CryptoHelpers.webCryptoToJwa(alg)).toEqual('RS384');
      });    
      
      it(`should return W3C for JWA 'ECDSA'`, () => {
        const alg = {name: 'ECDSA'};
        expect(CryptoHelpers.webCryptoToJwa(alg)).toEqual('ES256K');
      });    
      
      it(`should return W3C for JWA 'EDDSA'`, () => {
        const alg = {name: 'EDDSA'};
        expect(CryptoHelpers.webCryptoToJwa(alg)).toEqual('EdDSA');
      });    
      
      it(`should return W3C for JWA 'RSA-OAEP-256'`, () => {
        const alg = {name: 'RSA-OAEP-256'};
        expect(CryptoHelpers.webCryptoToJwa(alg)).toEqual('RSA-OAEP-256');
      });    
      
      it(`should return W3C for JWA 'RSA-OAEP'`, () => {
        const alg = {name: 'RSA-OAEP'};
        expect(CryptoHelpers.webCryptoToJwa(alg)).toEqual('RSA-OAEP-256');
      });    
      
      it(`should return W3C for JWA 'AES-GCM'`, () => {
        const alg = {name: 'AES-GCM'};
        expect(CryptoHelpers.webCryptoToJwa(alg)).toEqual('A128GCMKW');
      });    
      
      it(`should return W3C for JWA 'HMAC'`, () => {
        const alg = {name: 'HMAC'};
        expect(CryptoHelpers.webCryptoToJwa(alg)).toEqual('HS256');
      });    
      
      it(`should return W3C for JWA 'SHA-256'`, () => {
        const alg = {name: 'SHA-256'};
        expect(CryptoHelpers.webCryptoToJwa(alg)).toEqual('SHA-256');
      });    
      
      it(`should return W3C for JWA 'SHA-384'`, () => {
        const alg = {name: 'SHA-384'};
        expect(CryptoHelpers.webCryptoToJwa(alg)).toEqual('SHA-384');
      });    
      
      it(`should return W3C for JWA 'SHA-512'`, () => {
        const alg = {name: 'SHA-512'};
        expect(CryptoHelpers.webCryptoToJwa(alg)).toEqual('SHA-512');
      });    
      
      it(`should return JWA for W3C 'RSASSA-PKCS1-V1_5'`, () => {
        const alg = 'RS384';
        expect(CryptoHelpers.jwaToWebCrypto(alg)).toEqual({name: 'RSASSA-PKCS1-v1_5', hash:{ name: 'SHA-384'}});
      });    
      
      it(`should return JWA for W3C 'ECDSA'`, () => {
        const alg = 'ES256K';
        expect(CryptoHelpers.jwaToWebCrypto(alg)).toEqual({ name: 'ECDSA', namedCurve: 'secp256k1', crv: 'secp256k1', hash: { name: 'SHA-256' }});
      });    
      
      it(`should return JWA for W3C 'EDDSA'`, () => {
        const alg = 'EdDSA';
        expect(CryptoHelpers.jwaToWebCrypto(alg)).toEqual({ name: 'EDDSA', namedCurve: 'ed25519', crv: 'ed25519', hash: { name: 'SHA-256' } });
      });    
      
      it(`should return JWA for W3C 'RSA-OAEP-256'`, () => {
        const alg = 'RSA-OAEP-256';
        expect(CryptoHelpers.jwaToWebCrypto(alg)).toEqual({ name: 'RSA-OAEP-256', hash: 'SHA-256', modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]) });
      });    
      
      it(`should return JWA for W3C 'RSA-OAEP'`, () => {
        const alg = 'RSA-OAEP-256';
        expect(CryptoHelpers.jwaToWebCrypto(alg)).toEqual({ name: 'RSA-OAEP-256', hash: 'SHA-256', modulusLength: 2048, publicExponent: new Uint8Array([0x01, 0x00, 0x01]) });
      });    
      
      it(`should return JWA for W3C 'AES-GCM'`, () => {
        const alg = 'A128GCM';
        expect(CryptoHelpers.jwaToWebCrypto(alg, 'iv', 'aad')).toEqual({ name: W3cCryptoApiConstants.AesGcm, iv: 'iv', additionalData: 'aad', tagLength: 128,  length: 128 });
      });    
      
      it(`should return JWA for W3C 'HMAC'`, () => {
        const alg = 'HS256';
        expect(CryptoHelpers.jwaToWebCrypto(alg)).toEqual({name: 'HMAC', hash: {name: 'SHA-256'}});
      });    
      
      it(`should return JWA for W3C 'SHA-256'`, () => {
        const alg = 'SHA-256';
        expect(CryptoHelpers.jwaToWebCrypto(alg)).toEqual({hash: {name: 'SHA-256'}});
      });    
      
      it(`should return JWA for W3C 'SHA-384'`, () => {
        const alg = 'SHA-384';
        expect(CryptoHelpers.jwaToWebCrypto(alg)).toEqual({hash: {name: 'SHA-384'}});
      });    
      
      it(`should return JWA for W3C 'SHA-512'`, () => {
        const alg = 'SHA-512';
        expect(CryptoHelpers.jwaToWebCrypto(alg)).toEqual({hash: {name: 'SHA-512'}});
      });    
      
      it(`should return getKeyImportAlgorithm for JWA 'RSASSA-PKCS1-V1_5'`, () => {
        const alg = {name: 'RSASSA-PKCS1-V1_5', hash:'SHA-384'};
        expect(CryptoHelpers.getKeyImportAlgorithm(alg, {})).toEqual({name: 'RSASSA-PKCS1-V1_5', hash:{ name: 'SHA-384'}});
      });    
      /*
      it(`should return getKeyImportAlgorithm for JWA 'ECDSA'`, () => {
        const alg = {name: 'ECDSA', hash: { name: 'SHA-256' }};
        expect(CryptoHelpers.getKeyImportAlgorithm(alg, {crv: 'secp256k1'})).toEqual(<any>{ name: 'ECDSA', namedCurve: 'secp256k1', hash: { name: 'SHA-256' }});
      });    
      
      it(`should return getKeyImportAlgorithm for JWA 'EDDSA'`, () => {
        const alg = {name: 'EDDSA', hash: { name: 'SHA-256' }};
        expect(CryptoHelpers.getKeyImportAlgorithm(alg, {crv: 'ed25519'})).toEqual(<any>{ name: 'EDDSA', namedCurve: 'ed25519', hash: { name: 'SHA-256' }});
      });    
      
      it(`should return getKeyImportAlgorithm for JWA 'RSA-OAEP-256'`, () => {
        const alg = {name: 'RSA-OAEP-256'};
        expect(CryptoHelpers.getKeyImportAlgorithm(alg, {})).toEqual({ name: 'RSA-OAEP-256', hash: 'SHA-256' });
      });    
      
      it(`should return getKeyImportAlgorithm for JWA 'RSA-OAEP'`, () => {
        const alg = {name: 'RSA-OAEP'};
        expect(CryptoHelpers.getKeyImportAlgorithm(alg, {})).toEqual({ name: 'RSA-OAEP-256', hash: 'SHA-256' });
      });    
      
      it(`should return getKeyImportAlgorithm for JWA 'AES-GCM'`, () => {
        const alg = {name: 'AES-GCM'};
        expect(CryptoHelpers.getKeyImportAlgorithm(alg, {})).toEqual('A128GCMKW');
      });    
      
      it(`should return getKeyImportAlgorithm for JWA 'HMAC'`, () => {
        const alg = {name: 'HMAC'};
        expect(CryptoHelpers.getKeyImportAlgorithm(alg, {})).toEqual('HS256');
      });    
      
      it(`should return getKeyImportAlgorithm for JWA 'SHA-256'`, () => {
        const alg = {name: 'SHA-256'};
        expect(CryptoHelpers.getKeyImportAlgorithm(alg, {})).toEqual('SHA-256');
      });    
      
      it(`should return getKeyImportAlgorithm for JWA 'SHA-384'`, () => {
        const alg = {name: 'SHA-384'};
        expect(CryptoHelpers.getKeyImportAlgorithm(alg, {})).toEqual('SHA-384');
      });    
      
      it(`should return getKeyImportAlgorithm for JWA 'SHA-512'`, () => {
        const alg = {name: 'SHA-512'};
        expect(CryptoHelpers.getKeyImportAlgorithm(alg, {})).toEqual('SHA-512');
      });    */
    });