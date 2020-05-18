/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { PublicKey, RsaPublicKey, KeyType, KeyUse, KeyOperation } from "../lib/index";

 describe('PublicKey', () => {
  it('should create an instance of a PublicKey', () => {
    const publicKey = {
      kty: KeyType.RSA,
      use: KeyUse.Signature,
      alg: 'RS256',
      kid: '#key1',
      key_ops: [KeyOperation.Verify],
      n: 'nJLFTnqFZ2e0ozVoS_D5nDBFt-M3gm5O5XdtWK1VSuwmwszw7hAkReuMW8PdL28kOcEP3rwP-qCdwsB-V7fN8BiXZot8l2KX8rc-bvzChgjXn9aVCh1aaUlBDw68m5SyD3nvIpbDrYq5Uj32clgv5D6Et2MQu31otik604TROGjIg4S014ovh7vdfkYRpBfCPMerAauY6SuCk6XFJFFKxVzKsxfV1HXT8JPhj7GkXOL4NU1cL0a7xUKTDg_KmIT6AsrCAwa-Q-dKuU-7GuCtiQ0BukaYuW-ciJmXfTxwwE4E_Rm9PMckyh2oCjgttale6SbbvsGmtwnZSwSo9ZdDtQ',
      e: 'AQAB'
    };
    const key = new RsaPublicKey(publicKey);
    expect(key.kty).toEqual(KeyType.RSA);
    expect(key.use).toEqual(KeyUse.Signature);
    expect(key.kty).toEqual(KeyType.RSA);
    expect(key.alg).toEqual('RS256');
    expect(key.kid).toEqual('#key1');
    expect(key.key_ops).toEqual([KeyOperation.Verify]);
  });

  it('should calculate the same thumbprint as https://www.rfc-editor.org/rfc/rfc7638.html', async () =>{
    const referenceKey = '{"e":"AQAB","kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}';
    const publicKey: PublicKey = JSON.parse(referenceKey);
    expect(await PublicKey.getThumbprint(publicKey)).toEqual('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
  })
 });
