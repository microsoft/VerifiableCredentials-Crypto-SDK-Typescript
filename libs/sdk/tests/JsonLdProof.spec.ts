/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { CryptoBuilder, KeyUse, JoseBuilder, IPayloadProtectionSigning, CryptoFactoryNode, KeyStoreInMemory, Subtle, LongFormDid, KeyStoreOptions, Jose } from '../lib/index';
import { PublicKey } from 'verifiablecredentials-crypto-sdk-typescript-keys';
import base64url from 'base64url';
const bs58 = require('bs58');

describe('JSONLD proofs', () => {
    let originalTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
    beforeEach(async () => {
        jasmine.DEFAULT_TIMEOUT_INTERVAL = 10000;
    });

    afterEach(() => {
        jasmine.DEFAULT_TIMEOUT_INTERVAL = originalTimeout;
    });

    it('should sign and verify a credential', async () => {
        let crypto = new CryptoBuilder()
            .useSigningAlgorithm('EdDSA')
            .build();
        crypto = await crypto.generateKey(KeyUse.Signature);
        crypto = await crypto.generateKey(KeyUse.Signature, 'recovery');
        crypto.builder.useDid(await new LongFormDid(crypto).serialize());
        let jsonLdProofBuilder = new JoseBuilder(crypto)
        .useJsonLdProofsProtocol('JcsEd25519Signature2020')
        let jsonLdProof: IPayloadProtectionSigning = jsonLdProofBuilder.build();

        const doc = {
            '@context': [
                'https://www.w3.org/2018/credentials/v1',
                'https://www.w3.org/2018/credentials/examples/v1'
            ],
            'id': 'https://example.com/credentials/1872',
            'type': ['VerifiableCredential', 'AlumniCredential'],
            'issuer': 'https://example.edu/issuers/565049',
            'issuanceDate': '2010-01-01T19:23:24Z',
            'credentialSubject': {
                'id': 'did:example:ebfeb1f712ebc6f1c276e12ec21',
                'alumniOf': 'Example University'
            }
        };

        jsonLdProof = await jsonLdProof.sign(doc);
        const serialized = await jsonLdProof.serialize();
        const payload = JSON.parse(serialized);
        expect(payload.proof.type).toEqual('JcsEd25519Signature2020');
        const publicKey = (await crypto.builder.keyStore.get(crypto.builder.signingKeyReference, new KeyStoreOptions({ publicKeyOnly: true }))).getKey<PublicKey>();
        const result = await jsonLdProof.verify([publicKey]);
        expect(result).toBeTruthy();

        // Negative cases
        try {
            spyOn(Jose, 'payloadIsJsonLdProof').and.returnValue(['xxx', 'JcsEd25519Signature2020']);
            await jsonLdProof.deserialize(serialized + 'kkk');
        } catch (exception) {
            expect(exception).toEqual('Could not parse JSON LD token');
        }
        try {
            await jsonLdProof.serialize();
        } catch (exception) {
            expect(exception).toEqual('No token to serialize');
        }        
        try {
            await jsonLdProof.sign(Buffer.from('{}'));
        } catch (exception) {
            expect(exception).toEqual('Input to sign JSON LD must be an object');
        }        
        try {
            spyOn(jsonLdProofBuilder, 'getLinkedDataProofSuite').and.throwError('some error');
            await jsonLdProof.sign(doc);
        } catch (exception) {
            expect(exception).toEqual('some error');
        }
    });

    it('should validate reference vector for ed25519 signature 2020', async () => {
        // reference https://identity.foundation/JcsEd25519Signature2020/
        const doc = {
            "id": "did:test:36FC2p3yXoxcoVBn73qxPx",
            "publicKey": [
              {
                "id": "did:test:36FC2p3yXoxcoVBn73qxPx#key-1",
                "type": "Ed25519VerificationKey2018",
                "controller": "did:test:36FC2p3yXoxcoVBn73qxPx",
                "publicKeyBase58": "295nPvQHCdfXT8N275Hme434Z2NqZY5y3NN7rdts8Ew1"
              }
            ],
            "authentication": null,
            "service": [
              {
                "id": "test-service-1",
                "type": "test-service",
                "serviceEndpoint": "https://test-service.com/test-service"
              }
            ],
            "proof": {
              "created": "2020-09-24T16:43:29Z",
              "proofPurpose": "assertionMethod",
              "verificationMethod": "did:test:36FC2p3yXoxcoVBn73qxPx#key-1",
              "nonce": "fd2ccdaa-a9eb-4927-9ad2-3c0ad84546d5",
              "signatureValue": "2Ha72f5KqowpAeLxF2UvDBYgknLiHeBk9W6g7FHhPTd26M5qDgSfmWrpJareNp3bb9apwfUKysjFmbFcEN4LXLg7",
              "type": "JcsEd25519Signature2020"
            }
          };

        const publicKey = {
            kty: 'OKP',
            crv: 'ed25519',
            x: base64url.encode(Buffer.from('10edbdbe76a73351f28747303f47e98faa00ddd914c05c3dbaba0d6ecfef59a8', 'hex'))
        }
        let crypto = new CryptoBuilder()
            .useSigningAlgorithm('EdDSA')
            .build();
        let jsonLdProof: IPayloadProtectionSigning = new JoseBuilder(crypto)
            .build();
        jsonLdProof = await jsonLdProof.deserialize(JSON.stringify(doc));
        const result = await (<any>jsonLdProof).verify([publicKey]);
        expect(result).toBeTruthy();
    });
});