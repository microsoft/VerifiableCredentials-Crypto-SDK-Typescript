/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { KeyReference, CryptoBuilder, KeyUse, CryptoHelpers, CryptoFactoryScope, JsonWebKey, KeyContainer } from './index';
import { CryptoKey } from 'webcrypto-core';

/**
 * Class to model Crypto
 */
export default class Crypto {

  private signingKey: CryptoKeyPair | CryptoKey | undefined;

  constructor(
    private _builder: CryptoBuilder) {
  }

  /**
   * Gets the builder for the request
   */
  public get builder(): CryptoBuilder {
    return this._builder;
  }

  public async generateKey(keyUse: KeyUse) {
    if (keyUse === KeyUse.Signature) {
      const algorithm = CryptoHelpers.jwaToWebCrypto(this.builder.signingAlgorithm);
      const subtle = this.builder.cryptoFactory.getMessageSigner(this.builder.signingAlgorithm, CryptoFactoryScope.Private);

      this.signingKey = await subtle.generateKey(
        algorithm,
        this.builder.signingKeyIsExtractable,
        ['sign', 'verify'],
        {
          keyReference: this.builder.signingKeyReference
        });

      // export key
      let jwk: JsonWebKey;
      if ((<CryptoKeyPair>this.signingKey).privateKey) {
        jwk = <JsonWebKey>await subtle.exportKey('jwk', (<CryptoKeyPair>this.signingKey).privateKey);
      } else if ((<CryptoKeyPair>this.signingKey).publicKey) {
        this.builder.signingKeyReference!.cryptoKey = (<CryptoKeyPair>this.signingKey).publicKey;
        return this;
      } else {
        if (!this.builder.signingKeyIsExtractable) {
          return this;
        }
        jwk = <JsonWebKey>await subtle.exportKey('jwk', <CryptoKey>this.signingKey);
      }

      await this.builder.keyStore.save(this.builder.signingKeyReference!,jwk);
      return this;

    } else {
      throw new Error('not implemented');
    }
  }
}

