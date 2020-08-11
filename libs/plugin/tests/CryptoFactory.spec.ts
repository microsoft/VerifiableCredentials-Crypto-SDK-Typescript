/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { SubtleCryptoNode, CryptoFactory, CryptoFactoryScope } from '../lib/index';
import { KeyStoreInMemory, KeyReference } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import SubtleCryptoMock from './SubtleCryptoMock';
//import { SubtleCryptoElliptic } from '../../';

describe('CryptoFactory', () => {
  it('should create a crypto suite',() => {
    const keyStore = new KeyStoreInMemory();
    let keyReference = new KeyReference('', 'secret');

    const factory = new CryptoFactory(keyStore, SubtleCryptoNode.getSubtleCrypto());
    expect(factory).toBeDefined();
    const keyEncrypter = factory.getKeyEncrypter('*', CryptoFactoryScope.All, keyReference);
    expect(keyEncrypter).toBeDefined();
    const macSigner = factory.getMessageAuthenticationCodeSigner('*', CryptoFactoryScope.All, keyReference);
    expect(macSigner).toBeDefined();
    const messageDigest = factory.getMessageDigest('*', CryptoFactoryScope.All, keyReference);
    expect(messageDigest).toBeDefined();
    const messageSigner = factory.getMessageSigner('*', CryptoFactoryScope.All, keyReference);
    expect(messageSigner).toBeDefined();
    const sharedKeyEncrypter = factory.getSharedKeyEncrypter('*', CryptoFactoryScope.All, keyReference);
    expect(sharedKeyEncrypter).toBeDefined();
    const symmetricEncrypter = factory.getSymmetricEncrypter('*', CryptoFactoryScope.All, keyReference);
    expect(symmetricEncrypter).toBeDefined();
  });

  it('should change a crypto suite item',() => {
    const keyStore = new KeyStoreInMemory();
    
    const factory = new CryptoFactory(keyStore, SubtleCryptoNode.getSubtleCrypto());
    const algorithm = 'ES256K-tobeinvented';
    const subtleCrypto = new SubtleCryptoMock();
    let keyReference = new KeyReference('', 'secret');

    let keyEncrypters: any = factory.getKeyEncrypter(algorithm, CryptoFactoryScope.All, keyReference);
    expect(keyEncrypters.ID).toBeUndefined();

    factory.addKeyEncrypter(algorithm, {subtleCrypto: subtleCrypto, scope: CryptoFactoryScope.Private, keyStoreType: ['secret']});
    keyEncrypters = factory.getKeyEncrypter(algorithm, CryptoFactoryScope.Private, keyReference);
    expect(keyEncrypters.ID).toEqual('SubtleCryptoMock');
    keyEncrypters = factory.getKeyEncrypter(algorithm, CryptoFactoryScope.All, keyReference);
    expect(keyEncrypters.ID).toBeUndefined();
    factory.addKeyEncrypter(algorithm, {subtleCrypto: factory.defaultCrypto, scope: CryptoFactoryScope.All, keyStoreType: ['secret']});
    keyEncrypters = factory.getKeyEncrypter(algorithm, CryptoFactoryScope.All, keyReference);
    expect(keyEncrypters.ID).toBeUndefined();
    
    
    factory.addSharedKeyEncrypter(algorithm, {subtleCrypto: subtleCrypto, scope: CryptoFactoryScope.Private, keyStoreType: ['secret']});
    const sharedKeyEncrypters: any = factory.getSharedKeyEncrypter(algorithm, CryptoFactoryScope.Private, keyReference);
    expect(sharedKeyEncrypters.ID).toEqual('SubtleCryptoMock');
    
    factory.addSymmetricEncrypter(algorithm, {subtleCrypto: subtleCrypto, scope: CryptoFactoryScope.All, keyStoreType: ['secret']});
    const symmetricEncrypter: any = factory.getSymmetricEncrypter(algorithm, CryptoFactoryScope.All, keyReference);
    expect(symmetricEncrypter.ID).toEqual('SubtleCryptoMock');
    
    factory.addMessageSigner(algorithm, {subtleCrypto: subtleCrypto, scope: CryptoFactoryScope.All, keyStoreType: ['secret']});
    const messageSigner: any = factory.getMessageSigner(algorithm, CryptoFactoryScope.All, keyReference);
    expect(messageSigner.ID).toEqual('SubtleCryptoMock');

    factory.addMessageAuthenticationCodeSigner(algorithm, {subtleCrypto: subtleCrypto, scope: CryptoFactoryScope.All, keyStoreType: ['secret']});
    const messageAuthenticationCodeSigners: any = factory.getMessageAuthenticationCodeSigner(algorithm, CryptoFactoryScope.All, keyReference);
    expect(messageAuthenticationCodeSigners.ID).toEqual('SubtleCryptoMock');
    
    factory.addMessageDigest(algorithm, {subtleCrypto: subtleCrypto, scope: CryptoFactoryScope.All, keyStoreType: ['secret']});
    const messageDigests: any = factory.getMessageDigest(algorithm, CryptoFactoryScope.All, keyReference);
    expect(messageDigests.ID).toEqual('SubtleCryptoMock');
  });

  it ('should normalize a jwk', () => {
    const jwk = {
      crv: 'abc'
    };
    const subtle = SubtleCryptoNode.getSubtleCrypto();
    expect(subtle.keyImportTransform(jwk, CryptoFactoryScope.All)).toEqual(jwk);
    expect(subtle.keyImportTransform(jwk, CryptoFactoryScope.All)).toEqual(jwk);
    jwk.crv = 'K-256';
    expect(subtle.keyExportTransform(jwk, CryptoFactoryScope.All)).toEqual({crv: 'SECP256K1'});
    jwk.crv = 'secp256k1';
    expect(subtle.keyImportTransform(jwk, CryptoFactoryScope.All)).toEqual({crv: 'K-256'});
  });
});
