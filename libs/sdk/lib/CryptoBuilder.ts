/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { CryptoFactory, Crypto, Subtle, IKeyStore, KeyStoreFactory, CryptoFactoryManager, SubtleCryptoNode, KeyStoreInMemory, TokenCredential, KeyStoreOptions } from './index';
import { KeyReference } from 'verifiablecredentials-crypto-sdk-typescript-keystore';

export default class CryptoBuilder {
  // Set the default crypto state
  private _keyStore: IKeyStore = new KeyStoreInMemory();
  private _subtle: Subtle = new SubtleCryptoNode().getSubtleCrypto();
  private _cryptoFactory: CryptoFactory = new CryptoFactory(this.keyStore, this.subtle);

  private _recoveryKeyOptions: KeyStoreOptions = {
    publicKeyOnly: false,  // get private key, key vault only returns public key
    latestVersion: true    // take last version of the key
  };
  private _signingKeyOptions: KeyStoreOptions = {
    publicKeyOnly: false,  // get private key, key vault only returns public key
    latestVersion: true    // take last version of the key
  };
  private _signingAlgorithm: string = 'ES256K';
  private _recoveryAlgorithm: string = 'ES256K';
  private _did: string | undefined;

  // key references
  private _recoveryKeyName = `recovery-${this._recoveryAlgorithm}`;
  private _recoveryKeyReference: KeyReference = new KeyReference(this._recoveryKeyName, 'secret');
  private _signingKeyName = `signing-${this._signingAlgorithm}`;
  private _signingKeyReference: KeyReference  = new KeyReference(this._signingKeyName, 'secret');

  /**
   * Create a crypto builder to provide crypto capabilities
   */
  constructor() {
  }


  /**
   * Get the DID of the requestor
   */
  public get did() {
    return this._did;
  }

  /**
   * Set the DID of the app
   */
  public useDid(did: string): CryptoBuilder {
    this._did = did;
    return this;
  }

  /**
   * True is the signing key can be extracted from the key store
   */
  public get signingKeyIsExtractable(): boolean {
    if (this._signingKeyReference) {
      return this._signingKeyReference.type === 'secret';
    } else {
      return true;
    }
  }

  /**
   * Get the reference in the key store to the recovery key
   */
  public get recoveryKeyReference(): KeyReference {
    return this._recoveryKeyReference;
  }

  /**
   * Set the reference in the key store to the recovery key
   */
  public useRecoveryKeyReference(
    recoveryKeyReference: KeyReference,
    options: KeyStoreOptions = {
      publicKeyOnly: false,  // get private key, key vault only returns public key
      latestVersion: true    // take last version of the key
    }): CryptoBuilder {
    this._recoveryKeyReference = recoveryKeyReference;
    this._recoveryKeyOptions = options;
    return this;
  }

  /**
   * Get the reference in the key store to the signing key
   */
  public get signingKeyReference(): KeyReference {
    return this._signingKeyReference;
  }

  /**
   * Get the options for retrieving and storing signing keys in the key store
   */
  public get signingKeyOptions(): KeyStoreOptions {
    return this._signingKeyOptions;
  }

  /**
   * Set the reference in the key store to the signing key
   */
  public useSigningKeyReference(
    signingKeyReference: KeyReference,
    options: KeyStoreOptions = {
      publicKeyOnly: false,  // get private key, key vault only returns public key
      latestVersion: true    // take last version of the key
    }): CryptoBuilder {
    this._signingKeyReference = signingKeyReference;
    this._signingKeyOptions = options;
    return this;
  }

  /**
   * Get the algorithm used for signing
   */
  public get signingAlgorithm(): string {
    return this._signingAlgorithm;
  }

  /**
   * Get the algorithm used for recovery
   */
  public get recoveryAlgorithm(): string {
    return this._recoveryAlgorithm;
  }

  /**
   * Set the algortihm use for signing
   */
  public useSigningAlgorithm(signingAlgorithm: string): CryptoBuilder {
    this._signingAlgorithm = signingAlgorithm;
    return this;
  }

  /**
   * Gets the key store
   */
  public get keyStore(): IKeyStore {
    return this._keyStore;
  }

  /**
   * Gets the crypto factory
   */
  public get cryptoFactory(): CryptoFactory {
    return this._cryptoFactory;
  }

  /**
   * Sets the crypto factory
   */
  public useCryptoFactory(value: CryptoFactory): CryptoBuilder {
    this._cryptoFactory = value;
    this._keyStore = value.keyStore;
    return this;
  }

  /**
   * Gets the W3C subtle crypto web API
   */
  public get subtle(): Subtle {
    return this._subtle;
  }

  /**
   * Build the crypto object
   */
  public build(): Crypto {
    return new Crypto(this);
  }

  /**
   * Use Key Vault as keystore and crypto factory
   * @param tenantGuid Guid for the tenant
   * @param clientId Client id to access Key Vault
   * @param clientSecret Client secret to access Key Vault
   * @param vaultUri Vault uri
   */
  public useKeyVault(
    credential: TokenCredential,
    vaultUri: string
  ): CryptoBuilder {


    this._keyStore = KeyStoreFactory.create('KeyStoreKeyVault', credential, vaultUri);
    this._subtle = new SubtleCryptoNode().getSubtleCrypto();
    this._cryptoFactory = CryptoFactoryManager.create(
      'CryptoFactoryKeyVault',
      this.keyStore!,
      this.subtle!);

    // Check if default key references are used and switch to key as default for key vault
    if (this.signingKeyReference.keyReference === this._signingKeyName) {
      this.useSigningKeyReference(new KeyReference(this._signingKeyName, 'key'));
    }
    if (this.recoveryKeyReference.keyReference === this._recoveryKeyName) {
      this.useRecoveryKeyReference(new KeyReference(this._recoveryKeyName, 'key'));
    }

    return this;
  }
}