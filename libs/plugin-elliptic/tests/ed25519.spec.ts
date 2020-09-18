/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { SubtleCryptoElliptic, EllipticCurveKey } from '../src/index';
import base64url from 'base64url';
import { Subtle } from 'verifiablecredentials-crypto-sdk-typescript-plugin';
import { isJWK } from 'webcrypto-core';


const algGenerate = {
  name: 'EDDSA',
  namedCurve: 'ed25519'
};

describe('ed25519 - EDDSA', () => {
  let crypto: SubtleCryptoElliptic;
  // tslint:disable:mocha-no-side-effect-code
  const EC = require('elliptic');
  var eddsa = EC.eddsa;
  const ed25519 = new eddsa('ed25519');
  const messageReference = 'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc';
  const message = Buffer.from(messageReference);
  const secretReference = [0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60];
  const publicReference = [0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a];
  const signatureReference = '860c98d2297f3060a33f42739672d61b53cf3adefed3d3c672f320dc021b411e9d59b8628dc351e248b88b29468e0e41855b0fb7d83bb15be902bfccb8cd0a02'.toUpperCase();

  beforeAll(() => {
    crypto = new SubtleCryptoElliptic(new Subtle()).getSubtleCrypto();
  });

  it('should sign/verify a reference message with elliptic', async () => {
    const inverseSecret = [];
    for (let inx = secretReference.length - 1; inx > 0; inx--) {
      inverseSecret.push(secretReference[inx]);
    }

    const publicPair = ed25519.keyFromPublic(publicReference);
    const result = publicPair.verify(message, signatureReference);
    expect(result).toBeTruthy();

    const keyPair = ed25519.keyFromSecret(secretReference);
    let pub = keyPair.getPublic();
    expect(pub).toBeDefined();
    let signature = keyPair.sign(message).toHex();
    expect(signature.slice(0, 64)).toEqual(signatureReference.slice(0, 64));
    expect(signature.slice(64)).toEqual(signatureReference.slice(64));
  });

  it('should sign/verify a message with elliptic', async () => {
    const msg = [0xB, 0xE, 0xE, 0xF];
    const secret = Buffer.alloc(32, 0);
    const key = ed25519.keyFromSecret(secret);
    let d = base64url.encode(secret);
    let pub = key.getPublic();
    let x = base64url.encode(pub);
    expect(d).toBeDefined();
    expect(x).toBeDefined();
    let sig = key.sign(msg).toHex();
    var R = '8F1B9A7FDB22BCD2C15D4695B1CE2B063CBFAEC9B00BE360427BAC9533943F6C';
    var S = '5F0B380FD7F2E43B70AB2FA29F6C6E3FFC1012710E174786814012324BF19B0C';
    expect(sig.slice(0, 64)).toEqual(R);
    expect(sig.slice(64)).toEqual(S);
    let result = key.verify(msg, sig);
    expect(result).toBeTruthy();
    const importedPublic = ed25519.keyFromPublic(pub);
    expect(importedPublic.verify(msg, sig)).toBeTruthy();

    const importKey = ed25519.keyFromSecret(base64url.toBuffer(d));
    const newSig = importKey.sign(msg).toHex();
    expect(newSig).toEqual(sig);
  });

  it('should verify a message with elliptic', async () => {
    const msg = [101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 70, 90, 69, 82, 84, 81, 83, 73, 115, 73, 109, 73, 50, 78, 67, 73, 54, 90, 109, 70, 115, 99, 50, 85, 115, 73, 109, 78, 121, 97, 88, 81, 105, 79, 108, 115, 105, 89, 106, 89, 48, 73, 108, 49, 57, 46, 121, 113, 80, 10, 68, 208, 46, 208, 103, 142, 15, 103, 14, 7, 137, 6, 26, 209, 71, 246, 89, 188, 166, 57, 11, 130, 70, 76, 212, 228, 57, 53, 142, 38, 20, 151, 33, 33, 131, 196, 245, 77, 53, 79, 85, 251, 121, 41, 219, 244, 244, 226, 197, 166, 162, 50, 197, 197, 43, 28, 195, 228, 95, 245];
    const signature = [185, 80, 170, 165, 233, 238, 212, 94, 45, 156, 64, 52, 132, 6, 20, 213, 166, 241, 250, 78, 151, 11, 82, 116, 240, 249, 10, 71, 143, 198, 159, 18, 11, 245, 158, 237, 94, 233, 143, 216, 119, 36, 146, 82, 25, 228, 5, 29, 186, 118, 58, 250, 254, 225, 233, 72, 222, 6, 35, 197, 69, 68, 193, 15];
    const publicKeyHex = base64url.toBuffer('CV-aGlld3nVdgnhoZK0D36Wk-9aIMlZjZOK2XhPMnkQ').toString('hex');

    var key = ed25519.keyFromPublic(publicKeyHex, 'hex');
    let result = key.verify(msg, signature);
    expect(result).toBeTruthy();
  });

  it('should generate a key', async () => {
    const key = <CryptoKeyPair>(await crypto.generateKey(algGenerate, true, ['sign']));
    expect(key.publicKey.algorithm).toEqual(algGenerate);
    expect(key.publicKey.usages).toEqual(['sign']);
    expect(key.publicKey.type).toEqual('public');
    expect(key.privateKey.algorithm).toEqual(algGenerate);
    expect(key.privateKey.usages).toEqual(['sign']);
    expect(key.privateKey.type).toEqual('private');
  });

  it('should import and export a key', async () => {
    const key = <any>(await crypto.generateKey(algGenerate, true, ['sign']));
    const exported1 = await crypto.exportKey('jwk', key.privateKey);
    expect(exported1.kty).toEqual('OKP');
    expect(exported1.use).toEqual('sig');
    expect(exported1.crv).toEqual('ed25519');
    expect(exported1.alg).toEqual('EDDSA');
    expect(exported1.d).toBeDefined();
    expect(exported1.x).toBeDefined();
    expect(exported1.y).toBeUndefined();

    let imported: any = await crypto.importKey('jwk', exported1, algGenerate, true, ['sign']);
    let exported2 = await crypto.exportKey('jwk', imported);
    expect(exported2.kty).toEqual('OKP');
    expect(exported2.use).toEqual('sig');
    expect(exported2.crv).toEqual('ed25519');
    expect(exported2.d).toEqual(exported1.d);
    expect(exported2.x).toEqual(exported1.x);
    expect(exported2.y).toEqual(exported1.y);

    // import public key
    delete exported1.d;
    imported = await crypto.importKey('jwk', exported1, algGenerate, true, ['sign']);
    exported2 = await crypto.exportKey('jwk', imported);
    expect(exported1.kty).toEqual('OKP');
    expect(exported2.use).toEqual('sig');
    expect(exported2.crv).toEqual('ed25519');
    expect(exported2.d).toBeUndefined();
    expect(exported2.x).toEqual(exported1.x);
    expect(exported2.y).toEqual(exported1.y);
  });

  it('should verify evernyms reference message', async () => {
    const jwk = {
      'crv': 'Ed25519',
      'kty': "OKP",
      'd': 'QsI1MjsfmA4nL3zks3h0wfSTq6bqfM5nSacxWiUO_pg',
      'x': '5CW946ZRobK15OJjrL3O3ivW7_lsuekMpCrk8YH21pw'
    }
    const alg = { name: 'EDDSA', namedCurve: 'ed25519', hash: { name: 'SHA-256' } };
    let key: any = await crypto.importKey('jwk', jwk, alg, true, ['sign', 'verify']);

    const referenceMessage = Buffer.from('The rain in Spain stays mainly in the plain!');
    const signature = await crypto.sign(alg, key, referenceMessage);
    expect(base64url.encode(Buffer.from(signature))).toEqual('_9N24HjHV96A0vCJlkunCctJ44B-KN_BcBy3M2eX8LnFjFUPzb9w4Ek744HBj7H0arEK3uOgEzBCNzp-N8oJDA');

    delete jwk.d;
    key = await crypto.importKey('jwk', jwk, alg, true, ['sign', 'verify']);
    const result = await crypto.verify(alg, key, signature, referenceMessage);
    expect(result).toBeTruthy();
  });


  it('should sign a reference message', async () => {
    const jwk = {
      'crv': 'Ed25519',
      'kty': "OKP",
      'd': 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A',
      'x': '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo'
    }
    const alg = { name: 'EDDSA', namedCurve: 'ed25519', hash: { name: 'SHA-256' } };
    const key: any = await crypto.importKey('jwk', jwk, alg, true, ['sign', 'verify']);

    const signature = await crypto.sign(alg, key, message);
    const r = Buffer.from(signature.slice(0, 32));
    const s = Buffer.from(signature.slice(32));
    const R = Buffer.from(signatureReference.slice(0, 64), 'hex');
    const S = Buffer.from(signatureReference.slice(64), 'hex');
    expect(r).toEqual(R);
    expect(s).toEqual(S);
    const result = await crypto.verify(alg, key, signature, message);
    expect(result).toBe(true);
  });

  it('should sign and verify a message', async () => {
    const key: any = await crypto.generateKey(algGenerate, true, ['sign']);

    const data = 'abcdefg';
    const alg = { name: 'EDDSA', namedCurve: 'ed25519', hash: { name: 'SHA-256' } };
    const signature = await crypto.sign(alg, key.privateKey, Buffer.from(data));
    expect(signature.byteLength).toBeLessThanOrEqual(64);
    const publicKey: EllipticCurveKey = <EllipticCurveKey>key.publicKey;
    publicKey.usages = ['verify'];
    const result = await crypto.verify(alg, publicKey, signature, Buffer.from(data));
    expect(result).toBeTruthy();
  });

  it('should verify test vectors', async () => {
    const validate = async (reference: any) => {
      const alg = { name: 'EDDSA', namedCurve: 'ed25519', hash: { name: 'SHA-256' } };
      let cryptoKey: any;
      let signature: any;
      if (reference.jwk.d) {
        cryptoKey = await crypto.importKey('jwk', reference.jwk, alg, true, ['sign', 'verify']);
        signature = await crypto.sign(alg, cryptoKey, reference.referenceMessage);
        expect(Buffer.from(signature)).toEqual(reference.referenceSignature);
        delete reference.jwk.d;
      }
      cryptoKey = await crypto.importKey('jwk', reference.jwk, alg, true, ['sign', 'verify']);
      const result = await crypto.verify(alg, cryptoKey, reference.referenceSignature, reference.referenceMessage);
      expect(result).toBeTruthy();
    };

    const references = [
      {
        name: 'https://github.com/digitalbazaar/ed25519-verification-key-2018 reference',
        jwk: {
          crv: 'Ed25519',
          d: base64url.encode(Buffer.from('2b801f3b201aa161f015a64f58ae727734c38992e4a7e77e768eb471bac96b80', 'hex')),
          x: base64url.encode(Buffer.from('bc7648e7ba4532ce0e9c97e4729d104a8b47f4b6c34ffeb246d60ab7f6695295', 'hex')),
          kty: 'OKP'
        },
        referenceMessage: Buffer.from('746573742031323334', 'hex'),
        referenceSignature: Buffer.from('9e5402d5b545e9330de9c00426595118ae68ac79b9fa7e08878ea6b916204214e5f09f5247cd9f10fabb2040264fd1a9ac1adc44a273c54934128fb253ddb30a', 'hex')
      },
      {
        name: 'https://datatracker.ietf.org/doc/rfc8032/?include_text=1 test 2',
        jwk: {
          crv: 'Ed25519',
          d: base64url.encode(Buffer.from('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb', 'hex')),
          x: base64url.encode(Buffer.from('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', 'hex')),
          kty: 'OKP'
        },
        referenceMessage: Buffer.from([0x72]),
        referenceSignature: Buffer.from('92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00', 'hex')
      },
      {
        name: 'https://datatracker.ietf.org/doc/rfc8032/?include_text=1 test 1024',
        jwk: {
          crv: 'Ed25519',
          d: base64url.encode(Buffer.from('f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5', 'hex')),
          x: base64url.encode(Buffer.from('278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e', 'hex')),
          kty: 'OKP'
        },
        referenceMessage: Buffer.from('08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0', 'hex'),
        referenceSignature: Buffer.from('0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03', 'hex')
      },
      {
        name: 'https://github.com/transmute-industries/vc.js reference',
        jwk: {
          crv: 'Ed25519',
          d: base64url.encode(Buffer.from('9b937b81322d816cfab9d5a3baacc9b2a5febe4b149f126b3630f93a29527017', 'hex')),
          x: base64url.encode(Buffer.from('095f9a1a595dde755d82786864ad03dfa5a4fbd68832566364e2b65e13cc9e44', 'hex')),
          kty: 'OKP'
        },
        referenceMessage: Buffer.from('65794a68624763694f694a465a45525451534973496d49324e4349365a6d467363325573496d4e79615851694f6c7369596a5930496c31392e7971500a44d02ed0678e0f670e0789061ad147f659bca6390b82464cd4e439358e261497212183c4f54d354f55fb7929dbf4f4e2c5a6a232c5c52b1cc3e45ff5', 'hex'),
        referenceSignature: Buffer.from('b950aaa5e9eed45e2d9c4034840614d5a6f1fa4e970b5274f0f90a478fc69f120bf59eed5ee98fd87724925219e4051dba763afafee1e948de0623c54544c10f', 'hex')
      }
    ]
    for (let reference in references) {
      console.log(references[reference].name);
      await validate(references[reference]);
    }
  });

  it('should sign a message with DER format', async () => {
    const key = await crypto.generateKey(algGenerate, true, ['sign']);

    const data = 'abcdefg';
    const alg = { name: 'EDDSA', namedCurve: 'ed25519', hash: { name: 'SHA-256' }, format: 'DER' };
    const signature = await crypto.sign(alg, (<any>key).privateKey, Buffer.from(data));
    expect(signature.byteLength).toBeGreaterThanOrEqual(70);
    const publicKey: EllipticCurveKey = <EllipticCurveKey>(<any>key).publicKey;
    publicKey.usages = ['verify'];
    const result = await crypto.verify(alg, publicKey, signature, Buffer.from(data));
    expect(result).toBe(true);
  });

  it('should throw when no jwk key is exported', async () => {
    const key = <any>(await crypto.generateKey(algGenerate, true, ['sign']));
    let throws = false;
    await crypto.exportKey('raw', key.privateKey)
      .catch((err) => {
        throws = true;
        expect(err.message).toEqual(`Export key only supports jwk`);
      });
    expect(throws).toEqual(true);
  });

  it('should throw when no jwk key is imported', async () => {
    let throws = false;
    await crypto.importKey('raw', Buffer.from('aaaaaaaaaaaaa'), algGenerate, true, ['sign'])
      .catch((err) => {
        throws = true;
        expect(err.message).toEqual(`Import key only supports jwk`);
      });
    expect(throws).toEqual(true);
  });
});
