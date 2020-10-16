/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { KeyReference, CryptoBuilder, KeyUse, CryptoHelpers, CryptoFactoryScope, JsonWebKey, KeyContainer, IPayloadProtectionSigning, JoseBuilder } from './index';
import { CryptoKey } from 'webcrypto-core';

/**
 * Class to model Crypto
 */
export default class Crypto {

  // keep track of the signing key for the crypto object
  private signingKey: CryptoKeyPair | CryptoKey | undefined;

  // Set the protocols
  private _signingProtocols: { [protocol: string]: IPayloadProtectionSigning } = {
    JOSE: new JoseBuilder(this)
      .build(),
    JWT: new JoseBuilder(this)
      .useJwtProtocol()
      .build(),
    JSONLDProofs: new JoseBuilder(this)
      .build()
  };

  constructor(
    private _builder: CryptoBuilder) {
  }

  /**
   * Gets the builder for the request
   */
  public get builder(): CryptoBuilder {
    return this._builder;
  }

  public async generateKey(keyUse: KeyUse, type: string = 'signing') {
    let keyReference: KeyReference;
    let jwaAlalgorithm: string;
    switch (type) {
      case 'signing':
        keyReference = this.builder.signingKeyReference;
        jwaAlalgorithm = this.builder.signingAlgorithm
        break;
      case 'recovery':
        keyReference = this.builder.recoveryKeyReference;
        jwaAlalgorithm = this.builder.recoveryAlgorithm;
        break;
      default:
        throw new Error(`Key generation type '${type}' not supported`);
    }

    if (keyUse === KeyUse.Signature) {
      const w3cAlgorithm = CryptoHelpers.jwaToWebCrypto(jwaAlalgorithm);
      const importKey = keyReference?.type === 'secret';
      const subtle = this.builder.cryptoFactory.getMessageSigner(jwaAlalgorithm, CryptoFactoryScope.Private, keyReference);

      this.signingKey = await subtle.generateKey(
        w3cAlgorithm,
        this.builder.signingKeyIsExtractable,
        ['sign', 'verify'],
        {
          keyReference: keyReference
        });

      // export key
      let jwk: JsonWebKey;
      if ((<CryptoKeyPair>this.signingKey).privateKey) {
        keyReference!.cryptoKey = (<CryptoKeyPair>this.signingKey).privateKey;
        jwk = <JsonWebKey>await subtle.exportKey('jwk', (<CryptoKeyPair>this.signingKey).privateKey);
      } else if ((<CryptoKeyPair>this.signingKey).publicKey) {
        keyReference!.cryptoKey = (<CryptoKeyPair>this.signingKey).publicKey;
        return this;
      } else {
        if (!this.builder.signingKeyIsExtractable) {
          return this;
        }
        jwk = <JsonWebKey>await subtle.exportKey('jwk', <CryptoKey>this.signingKey);
      }

      jwk.use = keyUse;
      jwk.alg = jwaAlalgorithm;
      await this.builder.keyStore.save(keyReference, jwk);
      return this;

    } else {
      throw new Error('not implemented');
    }
  }

  /**
   * Get the protocol used for signing
   */
  public signingProtocol(type: string): IPayloadProtectionSigning {
    return this.signingProtocols[type];
  }

  public get signingProtocols(): { [protocol: string]: IPayloadProtectionSigning } {
    return this._signingProtocols;
  }

  /**
   * Set the  protocol used for signing
   */
  public useSigningProtocol(type: string, signingProtocol: IPayloadProtectionSigning): Crypto {
    this._signingProtocols[type] = signingProtocol;
    return this;
  }
}

