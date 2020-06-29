/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import base64url from "base64url";
import { JwsToken, IJwsSigningOptions } from '../lib/index'
import { KeyStoreInMemory, ProtectionFormat, KeyReference } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import { CryptoFactory, SubtleCryptoNode, CryptoFactoryScope } from 'verifiablecredentials-crypto-sdk-typescript-plugin';
import { CryptoFactoryNode } from 'verifiablecredentials-crypto-sdk-typescript-plugin-cryptofactory-suites';
import { KeyOperation, RsaPrivateKey, KeyContainer, OkpPrivateKey } from 'verifiablecredentials-crypto-sdk-typescript-keys';
import { IJwtSigningOptions } from "../lib/IJoseOptions";
import JwtProtocol from "../lib/JwtProtocol";
import JwtToken from "../lib/jwt/JwtToken";

describe('JwsToken  RSA', () => {
  it('should create a JWT', async () => {
    const payload = {
      firstName: 'Jules',
      lastName: 'Winnfield',
      profession: 'hitman',
      email: 'jules@pulpfiction.com'
    };

    const keyStore = new KeyStoreInMemory();
    const subtle = SubtleCryptoNode.getSubtleCrypto();
    const options: IJwtSigningOptions = {
      algorithm: <Algorithm>{name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256'},
      cryptoFactory: new CryptoFactory(keyStore, subtle),
      expiryInSeconds: 24 * 60 * 60
    };

    // generate and save key
    const key = await subtle.generateKey(
      {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 2048,
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
          hash: {name: "SHA-256"}
      },
      true, 
      ["sign", "verify"]);
    const jwk = await subtle.exportKey('jwk', key.privateKey);
    await keyStore.save(new KeyReference('key'), jwk);
      
    const token = new JwtToken(options);
    const signature = await token.sign(new KeyReference('key'), payload);
    expect(signature.getProtected().get('typ')).toEqual('JWT');

    const serialized = signature.serialize();
    expect(serialized.split('.').length).toEqual(3);
  });

});
