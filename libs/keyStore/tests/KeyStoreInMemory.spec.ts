/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { RsaPublicKey, KeyType, PublicKey, KeyContainer, OctKey, RsaPrivateKey, OkpPublicKey, EcPublicKey } from 'verifiablecredentials-crypto-sdk-typescript-keys';
import base64url from 'base64url';
import { KeyStoreInMemory, KeyStoreOptions, KeyReference } from '../lib/index';

describe('KeyStoreInMemory', () => {

  it('should list all keys in the store', async () => {
    const keyStore = new KeyStoreInMemory();
    const key1: RsaPublicKey = {
      kty: KeyType.RSA,
      kid: 'kid1',
      e: 'AAEE',
      n: 'xxxxxxxxx',
      alg: 'none'
    };
    const key2: RsaPublicKey = {
      kty: KeyType.RSA,
      kid: 'kid2',
      e: 'AAEE',
      n: 'xxxxxxxxx',
      alg: 'none'
    };
    const key3: OkpPublicKey = {
      kty: KeyType.OKP,
      kid: 'kid3',
      crv: 'ed25519',
      x: 'AAEE',
      alg: 'EdDSA'
    };
    const key4: EcPublicKey = {
      kty: KeyType.EC,
      kid: 'kid4',
      crv: 'secp256k1',
      x: 'AAEE',
      y: 'AAEE',
      alg: 'ECDSA'
    };
    await keyStore.save(new KeyReference('1'), key1);
    await keyStore.save(new KeyReference('1'), key2);
    await keyStore.save(new KeyReference('2'), <PublicKey>key3);
    await keyStore.save(new KeyReference('3'), <PublicKey>key4);
    let list = await keyStore.list();

    // tslint:disable-next-line: no-backbone-get-set-outside-model
    expect(list['1'].kids.length).toEqual(2);
    expect(list['1'].kty).toEqual(KeyType.RSA);
    expect(list['1'].kids[0]).toEqual('kid1');
    expect(list['1'].kids[1]).toEqual('kid2');
    // tslint:disable-next-line: no-backbone-get-set-outside-model
    expect(list['2'].kids.length).toEqual(1);
    expect(list['2'].kty).toEqual(KeyType.OKP);
    expect(list['2'].kids[0]).toEqual('kid3');
    let key: any = await keyStore.get(new KeyReference('2'), { publicKeyOnly: true });
    expect(key.keys[0].kty).toEqual(KeyType.OKP);
    expect(key.keys[0].kid).toEqual('kid3');
    key = await keyStore.get(new KeyReference('3'), { publicKeyOnly: true });
    expect(key.keys[0].kty).toEqual(KeyType.EC);
    expect(key.keys[0].kid).toEqual('kid4');

    const rsaKey: any = {
      kty: KeyType.RSA,
      kid: 'rsaKey',
      e: 'AAEE',
      n: 'xxxxxxxxx',
      p: 'AAEE',
      q: 'AAEE',
      dp: 'AAEE',
      dq: 'AAEE',
      qi: 'AAEE',
      alg: 'none'
    };
    await keyStore.save(new KeyReference('rsaKey'), rsaKey);
    key = await keyStore.get(new KeyReference('rsaKey'), { publicKeyOnly: true });
    expect(key.d).toBeUndefined();
    expect(key.p).toBeUndefined();
    expect(key.q).toBeUndefined();
    expect(key.dp).toBeUndefined();
    expect(key.dq).toBeUndefined();
    expect(key.qi).toBeUndefined();

    key = await keyStore.get(new KeyReference('rsaKey'));
    expect(key.keys[0].d).toBeUndefined();
    expect(key.keys[0].n).toBeDefined();
  });

  it('should save a string', async () => {
    const key = 'abcdef';
    const keyStore = new KeyStoreInMemory();
    await keyStore.save(new KeyReference('key'), key);
    const retrieved = await keyStore.get(new KeyReference('key'), new KeyStoreOptions({ publicKeyOnly: false }));
    expect(retrieved.keys.length).toEqual(1);
    expect((<any>retrieved.keys[0]).k).toEqual(base64url.encode(key));
  });

  it('should throw because an oct key does not have a public key', async () => {

    // Setup registration environment
    const jwk: any = new OctKey('AAEE');

    const keyStore = new KeyStoreInMemory();
    await keyStore.save(new KeyReference('key'), jwk);
    let throwCaught = false;
    const error = await keyStore.get(new KeyReference('key'), new KeyStoreOptions({ publicKeyOnly: true }))
      .catch((err) => {
        throwCaught = true;
        expect(err).toBe('A secret does not has a public key');
      });
    expect(error).toBeUndefined();
    expect(throwCaught).toBe(true);

  });

  it('should throw because an oct key does not have a public key', async () => {

    // Setup registration environment
    const jwk: any = new OctKey('AAEE');
    jwk.kty = 'AAA';

    // Fail because wrong key type
    const keyStore = new KeyStoreInMemory();
    await keyStore.save(new KeyReference('key'), jwk);
    let throwCaught = false;
    const error = await keyStore.get(new KeyReference('key'), new KeyStoreOptions({ publicKeyOnly: true }))
      .catch((err) => {
        throwCaught = true;
        expect(err).toBe('A secret does not has a public key');
      });
    expect(error).toBeUndefined();
    expect(throwCaught).toBe(true);

  });

  it('should throw because the key does not exist', async () => {
    // Setup registration environment
    const jwk: any = {
      kty: 'oct',
      use: 'sig',
      k: 'AAEE'
    };

    const keyStore = new KeyStoreInMemory();
    await keyStore.save(new KeyReference('key'), jwk);
    let throwCaught = false;
    const signature = await keyStore.get(new KeyReference('key1'))
      .catch((err) => {
        throwCaught = true;
        expect(err).toBe('key1 not found');
      });
    expect(signature).toBeUndefined();
    expect(throwCaught).toBe(true);
  });
});
