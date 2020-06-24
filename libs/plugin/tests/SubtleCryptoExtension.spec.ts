/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { SubtleCryptoNode, CryptoFactory, CryptoFactoryScope, CryptoHelpers, SubtleCryptoExtension } from '../lib';
import { KeyStoreInMemory, KeyReference } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import EcPrivateKey from 'verifiablecredentials-crypto-sdk-typescript-keys/dist/lib/ec/EcPrivateKey';
import { PublicKey } from 'verifiablecredentials-crypto-sdk-typescript-keys';


describe('SubtleCryptoExtension', () => {
  const keyStore = new KeyStoreInMemory();
  const cryptoFactory = new CryptoFactory(keyStore, new SubtleCryptoNode().getSubtleCrypto());
  const generator = new SubtleCryptoExtension(cryptoFactory);

  it('should generate an ECDSA key', async () => {
    const alg = CryptoHelpers.jwaToWebCrypto('Es256K');
    const key: any = <CryptoKey>await generator.generateKey(
      alg,
      true,
      ['sign', 'verify']
    );
    const jwk = await generator.exportJwkKey(alg, key.privateKey, CryptoFactoryScope.Private);
    expect(jwk.d).toBeDefined();
    expect(jwk.x).toBeDefined();
    expect(jwk.y).toBeDefined();
    expect(jwk.kty).toEqual('EC');
  });

  it('should generate an RSA key', async () => {
    const alg = CryptoHelpers.jwaToWebCrypto('RSA-OAEP');
    const key: any = <CryptoKey>await generator.generateKey(
      alg,
      true,
      ['encrypt', 'decrypt']
    );
    const jwk = await generator.exportJwkKey(alg, key.privateKey, CryptoFactoryScope.Private);
    expect(jwk.d).toBeDefined();
    expect(jwk.n).toBeDefined();
    expect(jwk.e).toBeDefined();
    expect(jwk.kty).toEqual('RSA');
  });

  it('should generate an oct key', async () => {
    const alg = CryptoHelpers.jwaToWebCrypto('A128GCM');
    const key: any = <CryptoKey>await generator.generateKey(
      alg,
      true,
      ['encrypt', 'decrypt']
    );
    const jwk = await generator.exportJwkKey(alg, key, CryptoFactoryScope.Private);
    expect(jwk.k).toBeDefined();
    expect(jwk.kty).toEqual('oct');
  });
  it('should sign a message', async () => {
    const keyStore = new KeyStoreInMemory();
    const factory = new CryptoFactory(keyStore, SubtleCryptoNode.getSubtleCrypto());
    const subtle = new SubtleCryptoExtension(factory);
    const alg = { name: 'ECDSA', namedCurve: 'secp256k1', hash: { name: 'SHA-256' }, format: 'DER' };

    const jwk = new EcPrivateKey({ "kid": "#signing", "kty": "EC", "use": "sig", "alg": "ES256K", "crv": "secp256k1", "x": "7RlJnsuYQuSNdpRAFwejCXZqsAccW_QKWw4dPmABBVA", "y": "nf0vn9ib6ObyLm4WaDWUe8g3gkEwo2jVbthS7R4MsaU", "d": "2PtA4bb6fXprFLfjIJsi5Cer8YAdEDVDomYNYK9ppkU" });
    await keyStore.save('key', jwk);
    const payload = Buffer.from('test');
    let signature = await subtle.signByKeyStore(alg, new KeyReference('key'), payload);
    expect(signature.byteLength).toBeGreaterThan(65);
    const publicKey = (await keyStore.get(new KeyReference('key'), {publicKeyOnly: true})).getKey<PublicKey>();
    let result = await subtle.verifyByJwk(alg, publicKey, signature, payload);
    expect(result).toBeTruthy();

    // without DER
    delete alg.format;
    signature = await subtle.signByKeyStore(alg, new KeyReference('key'), payload);
    expect(signature.byteLength).toBeLessThanOrEqual(64);
    result = await subtle.verifyByJwk(alg, publicKey, signature, payload);
    expect(result).toBeTruthy();
  });
  it('should sign a message with key reference options', async () => {
    const keyStore = new KeyStoreInMemory();
    const factory = new CryptoFactory(keyStore, SubtleCryptoNode.getSubtleCrypto());
    const subtle = new SubtleCryptoExtension(factory);
    const alg = { name: 'ECDSA', namedCurve: 'secp256k1', hash: { name: 'SHA-256' }, format: 'DER' };

    const jwk = new EcPrivateKey({ "kid": "#signing", "kty": "EC", "use": "sig", "alg": "ES256K", "crv": "secp256k1", "x": "7RlJnsuYQuSNdpRAFwejCXZqsAccW_QKWw4dPmABBVA", "y": "nf0vn9ib6ObyLm4WaDWUe8g3gkEwo2jVbthS7R4MsaU", "d": "2PtA4bb6fXprFLfjIJsi5Cer8YAdEDVDomYNYK9ppkU" });
    await keyStore.save('key', jwk);
    const payload = Buffer.from('test');
    let signature = await subtle.signByKeyStore(alg, new KeyReference('key'), payload);
    expect(signature.byteLength).toBeGreaterThan(65);
    const publicKey = (await keyStore.get(new KeyReference('key'), {publicKeyOnly: true})).getKey<PublicKey>();
    let result = await subtle.verifyByJwk(alg, publicKey, signature, payload);
    expect(result).toBeTruthy();
  });

  it('should create correct DER encoded sequence for a known failure', () => {
    // a R||S value generataed from a real signature and repro failiure
    const rs: ArrayBuffer[] = [
      new Uint8Array([0x00, 0x5B, 0x04, 0x89, 0x70, 0x74, 0xCC, 0xC4, 0x48, 0x37, 0x66, 0x56, 0x12, 0xA6, 0x9E, 0x6C, 0xC6, 0x4B, 0xF9, 0xC7, 0xF3, 0x87, 0xFD, 0x9B, 0xCA, 0x35, 0xC8, 0xC0, 0x5E, 0x73, 0xF2, 0xD1]).buffer,
      new Uint8Array([0xF6, 0xDF, 0x12, 0x92, 0xEF, 0xAA, 0xD6, 0x2F, 0x6E, 0xBE, 0xF4, 0xBA, 0x61, 0x1F, 0xE8, 0x4F, 0x98, 0x3E, 0xC4, 0x6E, 0x88, 0x0C, 0x1A, 0x20, 0xB8, 0x1B, 0x0C, 0x6F, 0xC8, 0xAE, 0xC1, 0x39]).buffer,
    ];

    const der = SubtleCryptoExtension.toDer(rs)
    const expected = '3044021F5B04897074CCC44837665612A69E6CC64BF9C7F387FD9BCA35C8C05E73F2D1022100F6DF1292EFAAD62F6EBEF4BA611FE84F983EC46E880C1A20B81B0C6FC8AEC139';
    expect(Buffer.from(der).toString('hex').toUpperCase()).toEqual(expected);
  });

  it('should correctly roundtrip from R||S signature to DER signature', () => {

    const scenarios = [
      {
        scenario: 'R is 247, S is 247',
        rs: '007F9625E7D0B625004848DFBBA23F05BF15951CF881D204F8A89192A980813A006E4DABFED97160C92C16F52378169AD98963A2DBF2F5DACB68C365D3DD4A8B',
        der: '3042021F7F9625E7D0B625004848DFBBA23F05BF15951CF881D204F8A89192A980813A021F6E4DABFED97160C92C16F52378169AD98963A2DBF2F5DACB68C365D3DD4A8B'
      },
      {
        scenario: 'R is 247, S is 248',
        rs: '005F7F8604A16C2D59EC0875D3DF621D8B8FB5CAA83538183EB9BE65378ECB5C00D6DA9084654B420EBB62FAA114DFB33B143E93ABBFA30963B4B630AFA0451B',
        der: '3043021F5F7F8604A16C2D59EC0875D3DF621D8B8FB5CAA83538183EB9BE65378ECB5C022000D6DA9084654B420EBB62FAA114DFB33B143E93ABBFA30963B4B630AFA0451B'
      },
      {
        scenario: 'R is 247, S is 255',
        rs: '004F0C7FD008D741A126BFEC4354972E375EECA43CA6DB93C4C4469C0C8B85494F77387CDC3330515E9B0B44007CC9C0DBC62DDDF478BC89246ADADA25594E84',
        der: '3043021F4F0C7FD008D741A126BFEC4354972E375EECA43CA6DB93C4C4469C0C8B854902204F77387CDC3330515E9B0B44007CC9C0DBC62DDDF478BC89246ADADA25594E84'
      },
      {
        scenario: 'R is 247, S is 256',
        rs: '001E4BC1121CCA5C745BD94AD4C9038CC6BCB7B429AA8F87D07F79EEA12DC14DFF7355548A2C668414CB26746928F740CD97CC55CCF409EF38C9AEB574BB2151',
        der: '3044021F1E4BC1121CCA5C745BD94AD4C9038CC6BCB7B429AA8F87D07F79EEA12DC14D022100FF7355548A2C668414CB26746928F740CD97CC55CCF409EF38C9AEB574BB2151'
      },
      {
        scenario: 'R is 248, S is 247',
        rs: '00D368ADF65B8E04BA7FC62933DE1E77A6F915D43562F7651281A927478BCA7A0068B37E4A7E1992ACE3F723B27C5943CE3D45DCDA368AF191F797539B358F94',
        der: '3043022000D368ADF65B8E04BA7FC62933DE1E77A6F915D43562F7651281A927478BCA7A021F68B37E4A7E1992ACE3F723B27C5943CE3D45DCDA368AF191F797539B358F94'
      },
      {
        scenario: 'R is 248, S is 248',
        rs: '00821962339420B3F73F4DA7E46AFD7654DE0AAEDF23C702AB4FF5A3165E352700D44659E935CD95F5734A8D5DC79FC5EECD6ADA1622D843102878E1C7D9CE04',
        der: '3044022000821962339420B3F73F4DA7E46AFD7654DE0AAEDF23C702AB4FF5A3165E3527022000D44659E935CD95F5734A8D5DC79FC5EECD6ADA1622D843102878E1C7D9CE04'
      },
      {
        scenario: 'R is 248, S is 255',
        rs: '00E31AE33E8D15EA1E64C4E411B87F52A06AD9FA67E0968FF43F585F63D12DF211590D3F4BF83C63B28C6EA6425B0E83E3C87EAEA15F2014E5EFC6982254E9DC',
        der: '3044022000E31AE33E8D15EA1E64C4E411B87F52A06AD9FA67E0968FF43F585F63D12DF2022011590D3F4BF83C63B28C6EA6425B0E83E3C87EAEA15F2014E5EFC6982254E9DC'
      },
      {
        scenario: 'R is 248, S is 256',
        rs: '00B1647CEE8B1E736D9198616801BC59FE920301C49DEC308803B986EE2DCA46F129FFB0E6EA8462F7D958B1D214239CDD5F51E754832CBC89A96BE84B5A98C1',
        der: '3045022000B1647CEE8B1E736D9198616801BC59FE920301C49DEC308803B986EE2DCA46022100F129FFB0E6EA8462F7D958B1D214239CDD5F51E754832CBC89A96BE84B5A98C1'
      },
      {
        scenario: 'R is 255, S is 247',
        rs: '1A5F03B216A8ABDBB25CD8596C71DD61F82949CA7E0C8F5AF15297A6BBA2D978002E415CA5198E7750D16ED4D312A9782341A89150134C0BD96DBE869C6F739E',
        der: '304302201A5F03B216A8ABDBB25CD8596C71DD61F82949CA7E0C8F5AF15297A6BBA2D978021F2E415CA5198E7750D16ED4D312A9782341A89150134C0BD96DBE869C6F739E'
      },
      {
        scenario: 'R is 255, S is 248',
        rs: '47A3D8BF86F7F212B14486E7FF5E66653CD1C12AA047604C02A8582D32C54C8600AAD92B3FBF50C79245D6F2FA41545A7B10C5254B66E1D89763A0CA147D1B94',
        der: '3044022047A3D8BF86F7F212B14486E7FF5E66653CD1C12AA047604C02A8582D32C54C86022000AAD92B3FBF50C79245D6F2FA41545A7B10C5254B66E1D89763A0CA147D1B94'
      },
      {
        scenario: 'R is 255, S is 255',
        rs: '6C35A6C0F0BE1858DA4275DD60E69EA174E20B3D6E66FD9E4A9C385BEE7F1DD12054DED0D1E5DED54F763C3B468333EE2E1116E8AE22A51A0FF521A0EBBE3C62',
        der: '304402206C35A6C0F0BE1858DA4275DD60E69EA174E20B3D6E66FD9E4A9C385BEE7F1DD102202054DED0D1E5DED54F763C3B468333EE2E1116E8AE22A51A0FF521A0EBBE3C62'
      },
      {
        scenario: 'R is 255, S is 256',
        rs: '51C57E68B628B11E98EBD0619F1AAA82F1A362832A0DDDD9DE3FF5CD709CC9A2C5D1AE439DE2E9256C76CFABB74E93493794D24756607C228668184FDFBB08E1',
        der: '3045022051C57E68B628B11E98EBD0619F1AAA82F1A362832A0DDDD9DE3FF5CD709CC9A2022100C5D1AE439DE2E9256C76CFABB74E93493794D24756607C228668184FDFBB08E1'
      },
      {
        scenario: 'R is 256, S is 247',
        rs: '89E44707362D657E3E1C52128783F2EB473159D279638C24720331683E475D360077FF30B48E601D02DEF4043350E2B2EDDA9E3B403EEFE38A9B8FDC3B44E088',
        der: '304402210089E44707362D657E3E1C52128783F2EB473159D279638C24720331683E475D36021F77FF30B48E601D02DEF4043350E2B2EDDA9E3B403EEFE38A9B8FDC3B44E088'
      },
      {
        scenario: 'R is 256, S is 248',
        rs: 'A00104D21C8D8F0CD55ABA7853B6CB8261F52F6BEB440FB194E7210FDDABECD60095C5264B70957D358AE6003E4DA83123F104EE71D24B543DD4332CDF77D70E',
        der: '3045022100A00104D21C8D8F0CD55ABA7853B6CB8261F52F6BEB440FB194E7210FDDABECD602200095C5264B70957D358AE6003E4DA83123F104EE71D24B543DD4332CDF77D70E'
      },
      {
        scenario: 'R is 256, S is 255',
        rs: 'EEA4D9BF154B1F5E060019520F7532F6E81AA799609EE4DBEAC3DD9E974C0F565490BD9AD3368DDFA16F3D2B14E0ECBECDDDC935A4B59488568460AC2465E8A0',
        der: '3045022100EEA4D9BF154B1F5E060019520F7532F6E81AA799609EE4DBEAC3DD9E974C0F5602205490BD9AD3368DDFA16F3D2B14E0ECBECDDDC935A4B59488568460AC2465E8A0'
      },
      {
        scenario: 'R is 256, S is 256',
        rs: 'ACFFCA0FD8FB2905B9B61358E4EA064D353E49FA799CE2163F4CC2763A7E553BD218A9A321FB8DE9C2240FDEED4CF1EDBF5D35C47D18195CBD7769E76790B22E',
        der: '3046022100ACFFCA0FD8FB2905B9B61358E4EA064D353E49FA799CE2163F4CC2763A7E553B022100D218A9A321FB8DE9C2240FDEED4CF1EDBF5D35C47D18195CBD7769E76790B22E'
      },
    ];

    for (let scenario of scenarios) {
      // first 64 chars of the string are r, next are s
      const rs: ArrayBuffer[] = [
        Uint8Array.from(Buffer.from(scenario.rs.substring(0, 64), 'hex')),
        Uint8Array.from(Buffer.from(scenario.rs.substring(64), 'hex'))
      ];

      const der = SubtleCryptoExtension.toDer(rs)
      expect(Buffer.from(der).toString('hex').toUpperCase()).toEqual(scenario.der, scenario.scenario + " to DER");

      // roundtrip back to R||S
      const derArray = new Uint8Array(der);
      const roundtripRS = SubtleCryptoExtension.fromDer(derArray);
      const r = SubtleCryptoExtension.toPaddedNumber(roundtripRS[0]);
      const s = SubtleCryptoExtension.toPaddedNumber(roundtripRS[1]);
      const rsHex = Buffer.from(r).toString('hex').toUpperCase() + Buffer.from(s).toString('hex').toUpperCase();
      expect(rsHex).toEqual(scenario.rs, scenario.scenario + " back to R||S");
    }
  });
});
