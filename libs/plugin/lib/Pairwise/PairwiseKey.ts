/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { SubtleCrypto } from '../index';
import { CryptoError, CryptoAlgorithm } from '@microsoft/crypto-keystore';
import { OctKey, PrivateKey, KeyTypeFactory, KeyType, IKeyContainer, W3cCryptoApiConstants, JoseConstants } from '@microsoft/crypto-keys';
import CryptoFactory, { CryptoFactoryScope } from "../CryptoFactory";
import RsaPairwiseKey from "./RsaPairwiseKey";
import EcPairwiseKey from "./EcPairwiseKey";

/**
 * Class to model pairwise keys
 */
 export default class PairwiseKey {

  /**
   * Get or set the crypto factory to use, containing the crypto suite and the key store.
   */
   private cryptoFactory: CryptoFactory;
 
   // Set of master keys for the different persona's
   private masterKeys: Map<string, Buffer> = new Map<string, Buffer>();

  /**
   * Create an instance of @class PairwiseKey.
   * @param cryptoFactory The crypto factory object.
   */
   public constructor (cryptoFactory: CryptoFactory) {
     this.cryptoFactory = cryptoFactory;
   }

  /**
   * Generate a pairwise key for the specified algorithms
   * @param algorithm for the key
   * @param seedReference Reference to the seed
   * @param personaId Id for the persona
   * @param peerId Id for the peer
   */
   public async generatePairwiseKey(algorithm: EcKeyGenParams | RsaHashedKeyGenParams, seedReference: string, personaId: string, peerId: string): Promise<PrivateKey> {
    const personaMasterKey: Buffer = await this.generatePersonaMasterKey(seedReference, personaId);

    const keyType = KeyTypeFactory.createViaWebCrypto(algorithm);
    switch (keyType) {
      case KeyType.EC:
      case KeyType.OKP:
        return EcPairwiseKey.generate(this.cryptoFactory, personaMasterKey, <EcKeyGenParams>algorithm, peerId);
      case KeyType.RSA:
        return RsaPairwiseKey.generate(this.cryptoFactory, personaMasterKey, <RsaHashedKeyGenParams>algorithm, peerId);
    
      default:
        throw new CryptoError(algorithm, `Pairwise key for type '${keyType}' is not supported.`);
    }
  } 

  /**
   * Generate a pairwise master key.
   * @param seedReference  The master seed for generating pairwise keys
   * @param personaId  The owner DID
   */
   private async generatePersonaMasterKey (seedReference: string, personaId: string): Promise<Buffer> {
    let mk: Buffer | undefined = this.masterKeys.get(personaId);

    if (mk) {
      return mk;
    }

    // Get the seed
    const jwk = <OctKey>(<IKeyContainer> await this.cryptoFactory.keyStore.get(seedReference, { publicKeyOnly: false})).getKey();

    // Get the subtle crypto
    const crypto: SubtleCrypto = this.cryptoFactory.getMessageAuthenticationCodeSigner(W3cCryptoApiConstants.Hmac, CryptoFactoryScope.Private);

    // Generate the master key
    const alg: CryptoAlgorithm = { name: W3cCryptoApiConstants.Hmac, hash: W3cCryptoApiConstants.Sha512 };
    const masterJwk = {
      kty: 'oct',
      alg: JoseConstants.Hs512,
      k: jwk.k
    };
    let key = await crypto.importKey('jwk', masterJwk, alg, false, ['sign']);
    const masterKey = await crypto.sign(alg, key, Buffer.from(personaId));
    mk = Buffer.from(masterKey);
    this.masterKeys.set(personaId, mk); 
    return mk;
  }
}
