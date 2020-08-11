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

describe('JwsToken standard RSA', () => {
  it('should run RFC 7515 A.2.  Example JWS Using RSASSA-PKCS1-v1_5 SHA-256', async () => {
    const payload = '{"iss":"joe",\r\n'+
    ' "exp":1300819380,\r\n'+
    ' "http://example.com/is_root":true}';
    const payloadBuffer = Buffer.from([123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10,
      32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 
      32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97,
      109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111,
      111, 116, 34, 58, 116, 114, 117, 101, 125]);
      expect(payload).toBeDefined();
      expect(payloadBuffer).toBeDefined();
    
      const keyStore = new KeyStoreInMemory();
      const subtle = SubtleCryptoNode.getSubtleCrypto();
      const options: IJwsSigningOptions = {
        algorithm: <Algorithm>{name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256'},
        cryptoFactory: new CryptoFactory(keyStore, subtle)
      };

      const privateKey = {
        e: 'AQAB',
        d: 'Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ',
        n: 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
        p: '4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc',
        q: 'uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc',
        dp: 'BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0',
        dq: 'h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU',
        qi: 'IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U',
        key_ops: [KeyOperation.Sign],
        alg: 'RS256'
      };
      const key = new RsaPrivateKey(privateKey);

      await keyStore.save(new KeyReference('key'), key);
      const jwsToken = new JwsToken(options);
      const signature = await jwsToken.sign(new KeyReference('key'), payloadBuffer, ProtectionFormat.JwsCompactJson);
      expect(signature).toBeDefined();
      const encodedPayload = 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
      const encodedProtected = 'eyJhbGciOiJSUzI1NiJ9';
      const encodedSignature = 'cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw';
      expect(base64url.encode(signature.signatures[0].signature)).toEqual(encodedSignature);

      // Verify signature
      const success = await signature.verify([key.getPublicKey()]);
      expect(success).toBeTruthy();      

      const compact = signature.serialize(ProtectionFormat.JwsCompactJson);
      expect(compact).toEqual(`${encodedProtected}.${encodedPayload}.${encodedSignature}`);

      const general = signature.serialize(ProtectionFormat.JwsGeneralJson);
      let parsed = JSON.parse(general);
      expect(parsed.payload).toEqual(encodedPayload);
      expect(parsed.signatures[0].signature).toEqual(encodedSignature);
      expect(parsed.signatures[0].protected).toEqual(encodedProtected);
       
      // the header should be undefined. commented out for moment to get to identiverse - todo
      //expect(parsed.signatures[0].header).toBeUndefined()

      const flat = signature.serialize(ProtectionFormat.JwsFlatJson);
      parsed = JSON.parse(flat);
      expect(parsed.payload).toEqual(encodedPayload);
      expect(parsed.signature).toEqual(encodedSignature);
      expect(parsed.protected).toEqual(encodedProtected);
      // the header should be undefined. commented out for moment to get to identiverse - todo
      // expect(parsed.header).toBeUndefined();

      });

});
describe('JwsToken standard ed25519', () => {
  it('should run RFC rfc8037 A.4.  Ed25519 Signing', async () => {
    const payload = 'Example of Ed25519 signing';
    const payloadBuffer = Buffer.from(payload);
    
    const keyStore = new KeyStoreInMemory();
    const factory = new CryptoFactoryNode(keyStore, SubtleCryptoNode.getSubtleCrypto());
    const subtle = factory.getMessageSigner('ed25519', CryptoFactoryScope.Private, new KeyReference('', 'secret'));
    const options: IJwsSigningOptions = {
        algorithm: <Algorithm>{name: 'EDDSA', hash: 'SHA-256'},
        cryptoFactory: factory
    };

    const priv = [0x9d, 0x61, 0xb1, 0x9d , 0xef , 0xfd , 0x5a , 0x60 , 0xba , 0x84 , 0x4a , 0xf4 , 0x92 , 0xec , 0x2c , 0xc4,
      0x44 , 0x49 , 0xc5 , 0x69 , 0x7b , 0x32 , 0x69 , 0x19 , 0x70 , 0x3b , 0xac , 0x03 , 0x1c , 0xae , 0x7f , 0x60];
    const testPriv = [];
    for (let inx=priv.length - 1; inx > 0 ; inx --) {
      testPriv.push(priv[inx]);
    }
    const privateKey = {
      'kty': 'OKP',
      'alg': 'EdDSA',
      'crv': 'Ed25519',
      'd': base64url.encode(Buffer.from(priv)),
      'x': '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo'
    };
    const key = new OkpPrivateKey(privateKey);

    await keyStore.save(new KeyReference('key'), key);
    const jwsToken = new JwsToken(options);
    const signature = await jwsToken.sign(new KeyReference('key'), payloadBuffer, ProtectionFormat.JwsCompactJson);
    expect(signature).toBeDefined();
    const encodedPayload = 'RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc';
    const encodedProtected = 'eyJhbGciOiJFZERTQSJ9';
    const encodedSignature = 'hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg';
    const calcSignature = base64url.encode(signature.signatures[0].signature);
    expect(calcSignature).toEqual(encodedSignature);

    // Verify signature
    const success = await signature.verify([key.getPublicKey()]);
    expect(success).toBeTruthy();      

    const compact = signature.serialize(ProtectionFormat.JwsCompactJson);
    expect(compact).toEqual(`${encodedProtected}.${encodedPayload}.${encodedSignature}`);

    const general = signature.serialize(ProtectionFormat.JwsGeneralJson);
    let parsed = JSON.parse(general);
    expect(parsed.payload).toEqual(encodedPayload);
    expect(parsed.signatures[0].signature).toEqual(encodedSignature);
    expect(parsed.signatures[0].protected).toEqual(encodedProtected);
       
    // the header should be undefined. commented out for moment to get to identiverse - todo
    //expect(parsed.signatures[0].header).toBeUndefined()

    const flat = signature.serialize(ProtectionFormat.JwsFlatJson);
    parsed = JSON.parse(flat);
    expect(parsed.payload).toEqual(encodedPayload);
    expect(parsed.signature).toEqual(encodedSignature);
    expect(parsed.protected).toEqual(encodedProtected);
    // the header should be undefined. commented out for moment to get to identiverse - todo
    // expect(parsed.header).toBeUndefined();

  });

});
