import { Crypto, KeyReference, JsonWebKey } from './index';
import { KeyStoreOptions } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import { IonDid } from '@decentralized-identity/ion-sdk';
const clone = require('clone');

/**
 * Helper class to work with long form DID's
 */
export default class LongFormDid {
  constructor(private crypto: Crypto, private services: any = []) {
   }

  /**
   * Create longform DID based on keys in crypto object
   */
  public async serialize(): Promise<string> {
    // See https://github.com/diafygi/webcrypto-examples for examples how to use the W3C web Crypto stamdard

    if (this.crypto.builder.signingAlgorithm !== 'ES256K') {
      return Promise.reject(new Error(`Longform DIDs only support ES256K. Signing algorithm: ${this.crypto.builder.signingAlgorithm}`));
    }

    if (this.crypto.builder.recoveryAlgorithm !== 'ES256K') {
      return Promise.reject(new Error(`Longform DIDs only support ES256K. Recovery algorithm: ${this.crypto.builder.recoveryAlgorithm}`));
    }

    if (this.crypto.builder.updateAlgorithm !== 'ES256K') {
      return Promise.reject(new Error(`Longform DIDs only support ES256K. Update algorithm: ${this.crypto.builder.updateAlgorithm}`));
    }

    let signingPublic: any;
    let recoveryKey: any;
    let updateKey: any;
  
    try {
      signingPublic = await (await this.crypto.builder.keyStore.get(this.crypto.builder.signingKeyReference, new KeyStoreOptions({ publicKeyOnly: true }))).getKey<JsonWebKey>();
      signingPublic = this.normalizeJwk(signingPublic);
      recoveryKey = await (await this.crypto.builder.keyStore.get(this.crypto.builder.recoveryKeyReference, new KeyStoreOptions({ publicKeyOnly: true }))).getKey<JsonWebKey>();
      recoveryKey = this.normalizeJwk(recoveryKey);
      updateKey = await (await this.crypto.builder.keyStore.get(this.crypto.builder.updateKeyReference, new KeyStoreOptions({ publicKeyOnly: true }))).getKey<JsonWebKey>();
      updateKey = this.normalizeJwk(updateKey);  
    } catch (exception) {
      return Promise.reject(exception);
    }
    
    // Create long-form did
    const didDocumentKeys: any = {
      id: this.crypto.builder.recoveryKeyReference.keyReference,
      type: "EcdsaSecp256k1VerificationKey2019",
      "publicKeyJwk": signingPublic,
      "purposes": [
        "authentication", "keyAgreement"
      ]
    };

    const document = {
      publicKeys: [didDocumentKeys],
      services: this.services
    };

    const longFormDid = IonDid.createLongFormDid({ recoveryKey, updateKey, document });
    return longFormDid;
  };


  private normalizeJwk(key: any): any {
    const jwk = clone(key);
    delete jwk.key_ops;
    delete jwk.ext;
    delete jwk.kid;
    delete jwk.use;
    delete jwk.alg;
    jwk.crv = 'secp256k1';
    return jwk;
  }
}