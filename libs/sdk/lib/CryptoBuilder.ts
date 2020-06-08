/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { JoseBuilder, CryptoFactory, Crypto, SubtleCrypto, IKeyStore, KeyStoreFactory, CryptoFactoryManager, SubtleCryptoNode, IPayloadProtection, IPayloadProtectionOptions, KeyStoreInMemory, IPayloadProtectionSigning, TokenCredential } from './index';

export default class CryptoBuilder {
  // Set the default state
  private _keyStore: IKeyStore = new KeyStoreInMemory();
  private _subtle: SubtleCrypto = new SubtleCryptoNode().getSubtleCrypto();
  private _cryptoFactory: CryptoFactory = new CryptoFactory(this.keyStore, this.subtle);

  private _payloadProtectionProtocol: IPayloadProtectionSigning = new JoseBuilder(this.build()).build();
  private _signingKeyReference: string | undefined;

  /**
   * Create a crypto builder to provide crypto capabilities
   * @param signingKeyReference Reference in the key store to the signing key
   */
  constructor() {
  }

  /**
   * Get the reference in the key store to the signing key
   */
  public get signingKeyReference(): string | undefined {
    return this._signingKeyReference;
  }

  /**
   * Set the reference in the key store to the signing key
   */
  public set signingKeyReference(signingKeyReference: string | undefined) {
    this._signingKeyReference = signingKeyReference;
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
  public useCryptoFactory(value: CryptoFactory) {
    this._cryptoFactory = value;
    return this;
  }

  /**
   * Gets the W3C subtle crypto web API
   */
  public get subtle(): SubtleCrypto {
    return this._subtle;
  }

  /**
   * Gets the payload protect protocol
   */
  public get payloadProtectionProtocol(): IPayloadProtectionSigning {
    return this._payloadProtectionProtocol;
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

    return this;
  }
}