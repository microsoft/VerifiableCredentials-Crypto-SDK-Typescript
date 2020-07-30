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

  private signingKey: CryptoKeyPair | CryptoKey | undefined;

  
  // Set the default protocol
  private _signingProtocol: IPayloadProtectionSigning = new JoseBuilder(this).build();

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
        if (this.builder.signingKeyReference) {
          keyReference = this.builder.signingKeyReference;
        } else {
          throw new Error('signingKeyReference is not defined in crypto');
        }
        jwaAlalgorithm = this.builder.signingAlgorithm
        break;
      case 'recovery':
        if (this.builder.recoveryKeyReference) {
          keyReference = this.builder.recoveryKeyReference;
        } else {
          throw new Error('recoveryKeyReference is not defined in crypto');
        }
        jwaAlalgorithm = this.builder.recoveryAlgorithm;
        break;
      default:
        throw new Error(`Key generation type '${type}' not supported`);
    }

    if (keyUse === KeyUse.Signature) {
      const w3cAlgorithm = CryptoHelpers.jwaToWebCrypto(jwaAlalgorithm);
      const importKey = keyReference?.type === 'secret';
      const subtle = importKey ?
        this.builder.subtle :
        this.builder.cryptoFactory.getMessageSigner(jwaAlalgorithm, CryptoFactoryScope.Private);

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

      await this.builder.keyStore.save(keyReference!, jwk);
      return this;

    } else {
      throw new Error('not implemented');
    }
  }
  
  /**
   * Get the protocol used for signing
   */
  public get signingProtocol(): IPayloadProtectionSigning {
    return this._signingProtocol;
  }

  /**
   * Set the  protocol used for signing
   */
  public  useSigningProtocol(signingProtocol: IPayloadProtectionSigning): Crypto {
    this._signingProtocol = signingProtocol;
    return this;
  }
}

