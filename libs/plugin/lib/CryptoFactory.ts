/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { IKeyStore, KeyReference } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import { Subtle } from './index';

// Label for default algorithm
const DEFAULT_ALGORITHM = '*';

/**
 * A definition for a plugin item
 */
export interface CryptoSuiteMapItem {
  /**
   * The subtle crypto API 
   */
  subtleCrypto: Subtle,

  /**
   * Scope to which the subtle crypto API applies
   */
  scope: CryptoFactoryScope

  /**
   * secret for secrets and key for keys
   */
  keyStoreType: string[]
}

/**
 * A dictionary of JWA encryption algorithm names to a crypto object
 */
export type CryptoSuiteMap = { [name: string]: CryptoSuiteMapItem[] };

/**
 * Defines the scope for the plugin
 */
export enum CryptoFactoryScope {
  /**
   * Plugin applied for all keys
   */
  All = 'all',

  /**
   * Plugin applied for private (secret) keys
   */
  Private = 'private',

  /**
   * Plugin applied for public keys
   */
  Public = 'public'
}

/**
 * Utility class to handle all CryptoSuite dependency injection.
 * A crypto factory is a suite of crypto operations which defines the mapping
 * between an algorithm and the library implementing it.
 */
export default class CryptoFactory {

  /**
   * The key encryptors
   */
  private keyEncrypters: CryptoSuiteMap;

  /**
   * The shared key encryptors
   */
  private sharedKeyEncrypters: CryptoSuiteMap;
  
  /**
   * The symmetric content encryptors
   */
  private symmetricEncrypter: CryptoSuiteMap;
  
  /**
   * The message signer
   */
  private messageSigners: CryptoSuiteMap;
  
  /**
   * The hmac operations
   */
  private messageAuthenticationCodeSigners: CryptoSuiteMap;
  
  /**
   * The digest operations
   */
  private messageDigests: CryptoSuiteMap;

  /**
   * Key store used by the CryptoFactory
   */
  public keyStore: IKeyStore;

  /**
   * Default subtle crypto used for e.g. hashing.
   */
  public defaultCrypto: Subtle;

  /**
   * Constructs a new CryptoRegistry
   * @param keyStore used to store private keys
   * @param defaultCrypto Default subtle crypto used for e.g. hashing.
   */
  constructor (keyStore: IKeyStore, defaultCrypto: Subtle) {
    this.keyStore = keyStore;
    this.defaultCrypto = defaultCrypto;
    this.keyEncrypters = {'*': [{ subtleCrypto: defaultCrypto, scope: CryptoFactoryScope.All, keyStoreType: ['secret']}]};
    this.sharedKeyEncrypters = {'*': [{ subtleCrypto: defaultCrypto, scope: CryptoFactoryScope.All, keyStoreType: ['secret']}]};
    this.symmetricEncrypter = {'*': [{ subtleCrypto: defaultCrypto, scope: CryptoFactoryScope.All, keyStoreType: ['secret']}]};
    this.messageSigners = {'*': [{ subtleCrypto: defaultCrypto, scope: CryptoFactoryScope.All, keyStoreType: ['secret']}]};
    this.messageAuthenticationCodeSigners = {'*': [{ subtleCrypto: defaultCrypto, scope: CryptoFactoryScope.All, keyStoreType: ['secret']}]};
    this.messageDigests = {'*': [{ subtleCrypto: defaultCrypto, scope: CryptoFactoryScope.All, keyStoreType: ['secret']}]};
  }

  /**
   * Sets the key encrypter plugin given the encryption algorithm's name
   * @param name The name of the algorithm
   * @param cryptoSuiteMapItem Array containing subtle crypto API's and their scope
   */
  public addKeyEncrypter (name: string, cryptoSuiteMapItem: CryptoSuiteMapItem ): void {
    this.addSubtleCrypto(this.keyEncrypters, name, cryptoSuiteMapItem);
  }

  /**
   * Gets the key encrypter object given the encryption algorithm's name
   * @param name The name of the algorithm
   * @param scope The requested scope
   * @returns The corresponding subtle crypto API
   */
  public getKeyEncrypter (name: string, scope: CryptoFactoryScope, keyReference: KeyReference): Subtle {
    return this.getSubtleCrypto(this.keyEncrypters, name, scope, keyReference);
  }

  /**
   * Sets the shared key encrypter plugin given the encryption algorithm's name
   * @param name The name of the algorithm
   * @param cryptoSuiteMapItem Array containing subtle crypto API's and their scope
   */
  public addSharedKeyEncrypter (name: string, cryptoSuiteMapItem: CryptoSuiteMapItem ): void {
    this.addSubtleCrypto(this.sharedKeyEncrypters, name, cryptoSuiteMapItem);
  }

  /**
   * Gets the shared key encrypter object given the encryption algorithm's name
   * Used for DH algorithms
   * @param name The name of the algorithm
   * @param scope The requested scope
   * @returns The corresponding subtle crypto API
   */
  getSharedKeyEncrypter (name: string, scope: CryptoFactoryScope, keyReference: KeyReference): Subtle {
    return this.getSubtleCrypto(this.sharedKeyEncrypters, name, scope, keyReference);
  }

  /**
   * Sets the SymmetricEncrypter object plugin given the encryption algorithm's name
   * @param name The name of the algorithm
   * @param cryptoSuiteMapItem Array containing subtle crypto API's and their scope
   */
  public addSymmetricEncrypter (name: string, cryptoSuiteMapItem: CryptoSuiteMapItem ): void {
    this.addSubtleCrypto(this.symmetricEncrypter, name, cryptoSuiteMapItem);
  }

  /**
   * Gets the SymmetricEncrypter object given the symmetric encryption algorithm's name
   * @param name The name of the algorithm
   * @param scope The requested scope
   * @returns The corresponding subtle crypto API
   */
  getSymmetricEncrypter (name: string, scope: CryptoFactoryScope, keyReference: KeyReference): Subtle {
    return this.getSubtleCrypto(this.symmetricEncrypter, name, scope, keyReference);
  }
  
  /**
   * Sets the message signer object plugin given the encryption algorithm's name
   * @param name The name of the algorithm
   * @param cryptoSuiteMapItem Array containing subtle crypto API's and their scope
   */
  public addMessageSigner (name: string, cryptoSuiteMapItem: CryptoSuiteMapItem ): void {
    this.addSubtleCrypto(this.messageSigners, name, cryptoSuiteMapItem);
  }

  /**
   * Gets the message signer object given the signing algorithm's name
   * @param name The name of the algorithm
   * @param scope The requested scope
   * @returns The corresponding subtle crypto API
   */
  getMessageSigner (name: string, scope: CryptoFactoryScope, keyReference: KeyReference): Subtle {
    return this.getSubtleCrypto(this.messageSigners, name, scope, keyReference);
  }

  /**
   * Sets the mmac signer object plugin given the encryption algorithm's name
   * @param name The name of the algorithm
   * @param cryptoSuiteMapItem Array containing subtle crypto API's and their scope
   */
  public addMessageAuthenticationCodeSigner (name: string, cryptoSuiteMapItem: CryptoSuiteMapItem ): void {
    this.addSubtleCrypto(this.messageAuthenticationCodeSigners, name, cryptoSuiteMapItem);
  }

  /**
   * Gets the mac signer object given the signing algorithm's name
   * @param name The name of the algorithm
   * @param scope The requested scope
   * @returns The corresponding subtle crypto API
   */
  getMessageAuthenticationCodeSigner (name: string, scope: CryptoFactoryScope, keyReference: KeyReference): Subtle {
    return this.getSubtleCrypto(this.messageAuthenticationCodeSigners, name, scope, keyReference);
  }

  /**
   * Sets the message digest object plugin given the encryption algorithm's name
   * @param name The name of the algorithm
   * @param cryptoSuiteMapItem Array containing subtle crypto API's and their scope
   */
  public addMessageDigest (name: string, cryptoSuiteMapItem: CryptoSuiteMapItem ): void {
    this.addSubtleCrypto(this.messageDigests, name, cryptoSuiteMapItem);
  }

  /**
   * Gets the message digest object given the digest algorithm's name
   * @param name The name of the algorithm
   * @param scope The requested scope
   * @returns The corresponding subtle crypto API
   */
  getMessageDigest (name: string, scope: CryptoFactoryScope, keyReference: KeyReference): Subtle {
    return this.getSubtleCrypto(this.messageDigests, name, scope, keyReference);
  }

    /**
   * Sets the subtle crypto API on the mapper for the algorithm
   * @param mapper The mapper defining the API's
   * @param name The name of the algorithm
   * @param cryptoSuiteMapItem The API and scope
   * @returns The corresponding crypto API
   */
  private addSubtleCrypto (mapper: CryptoSuiteMap, name: string, cryptoSuiteMapItem: CryptoSuiteMapItem): void {
    if (mapper[name]) {
      mapper[name].push(cryptoSuiteMapItem);
      return;
    }

    mapper[name] = [cryptoSuiteMapItem];
  }

    /**
   * Gets the subtle crypto API for the mapper
   * @param mapper The mapper defining the API's
   * @param name The name of the algorithm
   * @param scope The requested scope
   * @returns The corresponding crypto API
   */
   private getSubtleCrypto (mapper: CryptoSuiteMap, name: string, scope: CryptoFactoryScope, keyReference: KeyReference): Subtle {
    if (mapper[name]) {
      let mapping = mapper[name].filter(item => item.scope === scope && item.keyStoreType.includes(keyReference.type));
      if (mapping && mapping.length > 0) {
        return mapping[0].subtleCrypto;
      }
      // Check if the algorithm is defined for All scope
      mapping = mapper[name].filter(item => item.scope === CryptoFactoryScope.All && item.keyStoreType.includes(keyReference.type));
      if (mapping && mapping.length > 0) {
        return mapping[0].subtleCrypto;
      }
    }

    return mapper[DEFAULT_ALGORITHM][0].subtleCrypto;
  }

}
