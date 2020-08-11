/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { Subtle } from '../index';
import { W3cCryptoApiConstants, PrivateKey, KeyTypeFactory, KeyType, EcPrivateKey, JoseConstants } from 'verifiablecredentials-crypto-sdk-typescript-keys';
import { CryptoAlgorithm, CryptoError, KeyReference } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import base64url from "base64url";
import CryptoFactory, { CryptoFactoryScope } from "../CryptoFactory";

// Create and initialize EC context
const BN = require('bn.js');
const elliptic = require('elliptic').ec;
const secp256k1 = new elliptic('secp256k1');

const SUPPORTED_CURVES = ['K-256', 'P-256K', 'secp256k1', 'ed25519'];

/**
 * Class to model EC pairwise keys
 */
 export default class EcPairwiseKey {

  /**
   * Generate a pairwise key for the specified algorithms
   * @param cryptoFactory defining the key store and the used crypto api
   * @param personaMasterKey Master key for the current selected persona
   * @param algorithm for the key
   * @param peerId Id for the peer
   * @param extractable True if key is exportable
   */
  public static async generate(cryptoFactory: CryptoFactory, personaMasterKey: Buffer, algorithm: EcKeyGenParams, peerId: string): Promise<PrivateKey> {
    // This method is currently breaking the subtle crypto pattern and needs to be fixed to be platform independent
    // Get the subtle crypto
    const crypto: Subtle = cryptoFactory.getMessageAuthenticationCodeSigner(W3cCryptoApiConstants.Hmac, CryptoFactoryScope.Private, new KeyReference('', 'secret'));

    // Generate the master key
    const alg: CryptoAlgorithm = { name: W3cCryptoApiConstants.Hmac, hash: W3cCryptoApiConstants.Sha512 };
    const signingKey: JsonWebKey = {
      kty: 'oct',
      alg: JoseConstants.Hs512,
      k: base64url.encode(personaMasterKey)
    };

    const key = await crypto.importKey('jwk', signingKey, alg, false, ['sign']);
    const pairwiseKeySeed = await crypto.sign(alg, key, Buffer.from(peerId));
 
    if (SUPPORTED_CURVES.indexOf(algorithm.namedCurve) === -1) {
      throw new CryptoError(algorithm, `Curve ${algorithm.namedCurve} is not supported`);
    }
    
    let privateKey = new BN(Buffer.from(pairwiseKeySeed));
    privateKey = privateKey.umod(secp256k1.curve.n);
    const pair = secp256k1.keyPair({ priv: privateKey });
    const pubKey = pair.getPublic();
    const d = privateKey.toArrayLike(Buffer, 'be', 32);
    const x = pubKey.x.toArrayLike(Buffer, 'be', 32);
    const y = pubKey.y.toArrayLike(Buffer, 'be', 32);
    const pairwise =  <EcPrivateKey>{
      crv: algorithm.namedCurve,
      d: base64url.encode(d),
      x: base64url.encode(x),
      y: base64url.encode(y),
      kty:KeyTypeFactory.createViaWebCrypto(algorithm),
      // Need an algorithm for kid generation - todo
      kid: '#key1'
    };

    return new EcPrivateKey(pairwise);
  } 
}
