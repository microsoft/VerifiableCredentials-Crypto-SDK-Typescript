/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { IKeyStore } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import { SubtleCryptoElliptic } from 'verifiablecredentials-crypto-sdk-typescript-plugin-elliptic';
import { CryptoFactory, CryptoFactoryScope } from 'verifiablecredentials-crypto-sdk-typescript-plugin';

/**
 * Utility class to handle all CryptoFactory dependency injection for the environment browser.
 * In the same way a developer can add new CryptoFactory classes that support a different device.
 */
export default class CryptoFactoryBrowser extends CryptoFactory {

  /**
   * Constructs a new CryptoRegistry
   * @param keyStore used to store private keys
   * @param crypto The suite to use for dependency injection
   */
  constructor (keyStore: IKeyStore, crypto: any) {
    super(keyStore, crypto);
    const subtleCrypto: any = new SubtleCryptoElliptic(crypto);
    this.addMessageSigner('ES256K', {subtleCrypto, scope: CryptoFactoryScope.All});
    this.addMessageSigner('EdDSA', {subtleCrypto, scope: CryptoFactoryScope.All});
    this.algorithmTransform = CryptoFactoryBrowser.normalizeAlgorithm;
    this.keyTransformImport = CryptoFactoryBrowser.normalizeJwkImport;
    this.keyTransformExport = CryptoFactoryBrowser.normalizeJwkExport;
  }
}
