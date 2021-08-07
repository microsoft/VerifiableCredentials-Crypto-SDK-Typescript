/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import base64url from 'base64url';
import { KeyType, OkpPublicKey, PublicKey } from 'verifiablecredentials-crypto-sdk-typescript-keys';
import { LongFormDid, CryptoBuilder, IJsonLinkedDataProofSuite, JoseBuilder, KeyUse, KeyStoreOptions, IPayloadProtectionSigning } from '../lib';
import SuiteJcsEd25519Signature2020 from '../lib/suites/SuiteJcsEd25519Signature2020';

describe('SuiteJcsEd25519Signature2020', () => {
    it('should sign and verify a payload', async () => {
        let crypto = new CryptoBuilder()
            .useSigningAlgorithm('EdDSA')
            .build();
        crypto = await crypto.generateKey(KeyUse.Signature);
        crypto = await crypto.generateKey(KeyUse.Signature, 'recovery');
        const did = 'did:test:12345';
        crypto = crypto.builder.useDid(did).build();

        let jsonLdProofs = new JoseBuilder(crypto)
            .build();
        expect(crypto.builder.signingAlgorithm).toEqual('EdDSA');
        expect(jsonLdProofs.builder.getLinkedDataProofSuite(jsonLdProofs)).toEqual(jsonLdProofs.builder.linkedDataProofSuites['JcsEd25519Signature2020'](jsonLdProofs));

        let suite: IJsonLinkedDataProofSuite = new SuiteJcsEd25519Signature2020(jsonLdProofs);
        let payload: any = {
            prop1: 'prop1',
            prop2: 'prop2'
        };

        expect(suite.type).toEqual('JcsEd25519Signature2020');
        expect(suite.alg).toEqual('EdDSA');
        try {
            await suite.verify();
            fail('Should throw ' + 'Import a credential by deserialize');
        } catch (exception) {
            expect(exception.message).toEqual('Import a credential by deserialize');
        }

        let signedPayload = await suite.sign(payload);
        const serialized = suite.serialize(signedPayload);
        const pl = JSON.parse(serialized);
        expect(pl.proof.signatureValue).toBeDefined();
        expect(pl.prop1).toEqual('prop1');
        expect(pl.prop2).toEqual('prop2');

        // Verify
        signedPayload = suite.deserialize(serialized);
        const key = (await crypto.builder.keyStore.get(crypto.builder.signingKeyReference, new KeyStoreOptions({ publicKeyOnly: true }))).getKey<PublicKey>();
        let result = await suite.verify([key]);
        expect(result).toBeTruthy();
        result = await suite.verify([key], signedPayload);
        expect(result).toBeTruthy();

        // Add custom suite
        jsonLdProofs = new JoseBuilder(crypto)
            .useJsonLdProofsProtocol('mySuite', (signingProtocol: IPayloadProtectionSigning) => new SuiteJcsEd25519Signature2020(signingProtocol))
            .build();
        suite = jsonLdProofs.builder.getLinkedDataProofSuite(jsonLdProofs)
        signedPayload = await suite.sign(payload);
        expect(signedPayload).toBeDefined();

        // Negative cases
        try {
            await suite.sign(<any>undefined);
            fail('Should throw ' + 'JSON LD proof input is undefined');
        } catch (exception) {
            expect(exception.message).toEqual('JSON LD proof input is undefined');
        }

        try {
            await suite.sign(suite.sign(<any>' '));
            fail('Should throw ' + 'JSON LD proof input should be an object');
        } catch (exception) {
            expect(exception.message).toEqual('JSON LD proof input should be an object');
        }

        try {
            delete payload.proof;
            suite.deserialize(JSON.stringify(payload));
            await suite.verify([key]);
            fail('Should throw ' + 'No proof to validate in signedPayload');
        } catch (exception) {
            expect(exception.message).toEqual('No proof to validate in signedPayload');
        }

        try {
            payload['proof'] = {};
            suite.deserialize(JSON.stringify(payload));
            await suite.verify([key]);
            fail('Should throw ' + 'Proof does not contain the signatureValue');
        } catch (exception) {
            expect(exception.message).toEqual('Proof does not contain the signatureValue');
        }
    });

    it('should return default suite', () =>{
        const jsonLdProofs = new JoseBuilder(new CryptoBuilder().build())
            .build();
        
        const suite = jsonLdProofs.builder.getLinkedDataProofSuite(jsonLdProofs);
        expect(suite.type).toEqual('JcsEd25519Signature2020'); 

        // Negative cases
        expect(() => jsonLdProofs.builder.getLinkedDataProofSuite(jsonLdProofs, 'xxx')).toThrowError(`Suite 'xxx' does not exist. Use jsonBuilder.useJsonLdProofsProtocol() to specify the suite to use.`);
    });

    it('should verify a reference payload', async () => {
        const vectors = [{
            payload: {
                "modelVersion": "1.0",
                "@context": [
                    "https://www.w3.org/2018/credentials/v1"
                ],
                "id": "4c93b0a8-2066-4bfc-aaa3-92a8d210352b",
                "type": [
                    "VerifiableCredential",
                    "https://credentials.workday.com/docs/specification/v1.0/credential.json"
                ],
                "issuer": "did:work:VZGS6FUkHMZdmMdD2KLXhZ",
                "issuanceDate": "2020-09-11T16:52:56Z",
                "credentialSchema": {
                    "id": "did:work:VS1wWC93J7TSwoKBCFYE9r;id=c8c4d927-247f-4244-b8d7-43ba8ed34902;version=1.0",
                    "type": "JsonSchemaValidatorWorkday2019"
                },
                "credentialSubject": {
                    "EmployeeName": "Virindh",
                    "Employer": "Engineering ",
                    "JobTitle": "Hello",
                    "id": "did:work:KwweCDcq3DJEsi31MwdyD6"
                },
                "claimProofs": {
                    "EmployeeName": {
                        "created": "2020-09-11T16:52:57Z",
                        "verificationMethod": "did:work:VZGS6FUkHMZdmMdD2KLXhZ#key-1",
                        "nonce": "33f92d8c-0f50-414e-880b-21984b00ccde",
                        "signatureValue": "35XbBG5tP8SnvJPaaB9rR8PFtrj75qZEYuBMZZQw1CFv7WGs2L5CS9WpS7PddWTrVT9FEotZBYLNCXjfnwKrHnyo",
                        "type": "JcsEd25519Signature2020"
                    },
                    "Employer": {
                        "created": "2020-09-11T16:52:57Z",
                        "verificationMethod": "did:work:VZGS6FUkHMZdmMdD2KLXhZ#key-1",
                        "nonce": "32b6d77c-f881-4cbe-87ff-1fa90ba7488e",
                        "signatureValue": "2DXfxYmZ9vgLvLDdm3VWZ58J58tKsVgNuQLRki28vkHskoheMyZsXJrCB44fAG4eaVmBxnraDg5JP6CiZqSZz5T5",
                        "type": "JcsEd25519Signature2020"
                    },
                    "JobTitle": {
                        "created": "2020-09-11T16:52:57Z",
                        "verificationMethod": "did:work:VZGS6FUkHMZdmMdD2KLXhZ#key-1",
                        "nonce": "30ebf349-bae9-44d8-a6d1-a4a38cd12fc0",
                        "signatureValue": "2LURxBkLuFqb9gT6q4cdbZ8WsLTGVsyEffhi3KwVuAa7GMFmHqQ6QNDWJj8QCU2ZFDqegcU9CrL6Rfy851wMeP6A",
                        "type": "JcsEd25519Signature2020"
                    },
                    "id": {
                        "created": "2020-09-11T16:52:57Z",
                        "verificationMethod": "did:work:VZGS6FUkHMZdmMdD2KLXhZ#key-1",
                        "nonce": "069d8c74-123d-4ec4-acab-5c5698735423",
                        "signatureValue": "41hpJtKF5NWhS3PYyyn4nzQG7qCf9wmcL1xYMCGJ5x1mb3gptvNFFXyNTLqERz4NXqBz91f7nxyMRfiZf533DTzy",
                        "type": "JcsEd25519Signature2020"
                    }
                },
                "proof": {
                    "created": "2020-09-11T16:52:57Z",
                    "verificationMethod": "did:work:VZGS6FUkHMZdmMdD2KLXhZ#key-1",
                    "nonce": "c7f62945-825f-49e7-abac-f077676ab503",
                    "signatureValue": "4sKb6mrobowt4yK8bG55ckLf8JpoUCDk7GXoSmGWaBvzJL1Q1MWxUa5EN8bsTRw5AggyTXHjb98ZeH8WkWC8oUJf",
                    "type": "JcsEd25519Signature2020"
                }
            },
            publicKey: {
                x: base64url.encode(Buffer.from('e741319c80aa1d2094dcb1235de46620563ee6197baa0d51c3ccb83ef2e0e040', 'hex')),
                crv: 'ed25519',
                kty: KeyType.OKP,
                alg: 'EdDSA'
            }
        }];
        let crypto = new CryptoBuilder()
            .useSigningAlgorithm('EdDSA')
            .build();

        const jsonLdProofs = new JoseBuilder(crypto)
            .build();

        let suite: IJsonLinkedDataProofSuite = new SuiteJcsEd25519Signature2020(jsonLdProofs);

        for (let vector in vectors) {
            const payload = vectors[vector].payload;
            const jwk: OkpPublicKey = vectors[vector].publicKey;

            // Verify
            const credential = suite.deserialize(JSON.stringify(payload));
            const result = await suite.verify([jwk], credential);
            expect(result).toBeTruthy();
        }
    });
});