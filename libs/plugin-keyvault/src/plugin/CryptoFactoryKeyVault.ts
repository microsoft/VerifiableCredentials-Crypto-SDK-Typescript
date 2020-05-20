/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { CryptoFactory, CryptoFactoryScope } from 'verifiablecredentials-crypto-sdk-typescript-plugin';
import { SubtleCryptoKeyVault, KeyStoreKeyVault } from '../index';
import { IKeyStore } from 'verifiablecredentials-crypto-sdk-typescript-keystore';

/**
 * Utility class to handle all CryptoFactory dependency injection for the environment CryptoFactoryKeyVault.
 * In the same way a developer can add new CryptoFactory classes that support a different device.
 */
export default class CryptoFactoryKeyVault extends CryptoFactory {
  /**
   * Constructs a new CryptoRegistry
   * @param keyStore used to store private jeys
   * @param defaultCrypto Default subtle crypto used for e.g. hashing.
   */
  constructor (keyStore: IKeyStore, defaultCrypto: any) {
    super(keyStore, defaultCrypto);
    const subtleCrypto: any = new SubtleCryptoKeyVault(defaultCrypto, <KeyStoreKeyVault>keyStore);
    this.addMessageSigner('ES256K', {subtleCrypto, scope: CryptoFactoryScope.Private});
    this.addMessageSigner('ECDSA', {subtleCrypto, scope: CryptoFactoryScope.Private});
    this.addKeyEncrypter('RSA-OAEP', {subtleCrypto, scope: CryptoFactoryScope.Private});
    this.addKeyEncrypter('RSA-OAEP-256', {subtleCrypto, scope: CryptoFactoryScope.Private});
    /*
    this.algorithmTransform = (algorithm: Algorithm) => {
      if ((<any>algorithm).namedCurve) {
        if ((<any>algorithm).namedCurve === 'SECP256K1') {
          const alg = clone(algorithm);
          alg.namedCurve = 'P-256K';
          return alg;
        }
      }

      return algorithm;
    };
    */
    this.algorithmTransform = (jwk: any) => { return jwk; } 
      this.keyTransformImport = (jwk: any, scope: CryptoFactoryScope) => { 
        if (scope === CryptoFactoryScope.Private) {
          return jwk; 
        }
        return CryptoFactory.normalizeJwkImport(jwk);
      } 
    }
}
