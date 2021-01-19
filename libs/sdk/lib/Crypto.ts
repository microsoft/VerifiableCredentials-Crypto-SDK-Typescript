/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { KeyReference, CryptoBuilder, KeyUse, CryptoHelpers, CryptoFactoryScope, JsonWebKey, KeyContainer, IPayloadProtectionSigning, JoseBuilder, Subtle } from './index';
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
      .useJsonLdProofsProtocol('JcsEd25519Signature2020')
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

  /**
   * Get the protocol used for signing
   */
  public signingProtocol(type: string): IPayloadProtectionSigning {
    return this.signingProtocols[type];
  }

  public get signingProtocols(): { [protocol: string]: IPayloadProtectionSigning } {
    return this._signingProtocols;
  }

  public async generateKey(keyUse: KeyUse, type: string = 'signing'): Promise<Crypto> {
    let keyReference: KeyReference;
    let jwaAlgorithm: string;
    switch (type) {
      case 'signing':
        keyReference = this.builder.signingKeyReference;
        jwaAlgorithm = this.builder.signingAlgorithm
        break;
      case 'recovery':
        keyReference = this.builder.recoveryKeyReference;
        jwaAlgorithm = this.builder.recoveryAlgorithm;
        break;
      case 'update':
        keyReference = this.builder.updateKeyReference;
        jwaAlgorithm = this.builder.updateAlgorithm;
        break;
      default:
        return Promise.reject(new Error(`Key generation type '${type}' not supported`));
    }

    if (keyUse === KeyUse.Signature) {
      const w3cAlgorithm = CryptoHelpers.jwaToWebCrypto(jwaAlgorithm);
      const importKey = keyReference?.type === 'secret';
      const subtle = this.builder.cryptoFactory.getMessageSigner(jwaAlgorithm, CryptoFactoryScope.Private, keyReference);

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
      jwk.alg = jwaAlgorithm;
      await this.builder.keyStore.save(keyReference, jwk);
      return this;

    } else {
      return Promise.reject(new Error('not implemented'));
    }
  }
}

