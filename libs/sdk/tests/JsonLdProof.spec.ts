/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { CryptoBuilder, KeyUse, JoseBuilder, IPayloadProtectionSigning, CryptoFactoryNode, KeyStoreInMemory, Subtle, LongFormDid, KeyStoreOptions } from '../lib/index';
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

    fit('should sign and verify a credential', async () => {
        let crypto = new CryptoBuilder()
            .useSigningAlgorithm('EdDSA')
            .build();
        crypto = await crypto.generateKey(KeyUse.Signature);
        crypto = await crypto.generateKey(KeyUse.Signature, 'recovery');
        crypto.builder.useDid(await new LongFormDid(crypto).serialize());
        let jsonLdProof: IPayloadProtectionSigning = new JoseBuilder(crypto)
            .uselinkedDataProofsProtocol()
            .build();

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
        const publicKey = (await crypto.builder.keyStore.get(crypto.builder.signingKeyReference, new KeyStoreOptions({ publicKeyOnly: true }))).getKey<PublicKey>();
        const result = await jsonLdProof.verify([publicKey]);
        expect(result).toBeTruthy();
    });

    it('should validate test vectors', async () => {
        const credential = require('./testVectors/credential.json');
        const keypair = require('./testVectors/keypair.json');
        const serialized = JSON.stringify(credential.vc_0);
        let crypto = new CryptoBuilder()
            .useSigningAlgorithm('EdDSA')
            .build();
        await crypto.builder.keyStore.save(crypto.builder.signingKeyReference, keypair.keypair_0);
        let jsonLdProof: IPayloadProtectionSigning = new JoseBuilder(crypto)
            .uselinkedDataProofsProtocol()
            .build();
        jsonLdProof = jsonLdProof.deserialize(JSON.stringify(credential.vc_0));
        const keyContainer = await crypto.builder.keyStore.get(crypto.builder.signingKeyReference, new KeyStoreOptions({ publicKeyOnly: true }));
        const publicKey = keyContainer.getKey<PublicKey>();
        const result = await jsonLdProof.verify([publicKey]);
        expect(result).toBeTruthy();
        console.log(serialized);
    });
    it('should validate reference vector for ed25519 signature 2020', async () => {
        const sign = bs58.decode('6b23ioXQSAayuw13PGFMCAKqjgqoLTpeXWCy5WRfw28c').toString('hex');
        const doc = {
            "id": "did:example:123",
            "publicKey": [
                {
                    "id": "did:example:123#key-1",
                    "type": "JcsEd25519Key2020",
                    "controller": "did:example:123",
                    "publicKeyBase58": "6b23ioXQSAayuw13PGFMCAKqjgqoLTpeXWCy5WRfw28c"
                }
            ],
            "service": [
                {
                    "id": "schemaID",
                    "type": "schema",
                    "serviceEndpoint": "schemaID"
                }
            ],
            "proof": {
                "created": "2020-04-17T18:03:18Z",
                "verificationMethod": "did:example:123#key-1",
                "nonce": "7bc22433-2ea4-4d30-abf2-2652bebb26c7",
                "type": "JcsEd25519Signature2020",
                "signatureValue": "5TcawVLuoqRjCuu4jAmRqBcKoab1YVqxG8RXnQwvQBHNwP7RhPwXhzhTLVu3dKGposo2mmtfx9AwcqB2Mwnagup1JT5Yr9u3SjzLCc6kx4wW6HG5SKcra4SauhutN94s8Eo"
            }
        };

        const publicKey = {
            kty: 'OKP',
            crv: 'ed25519',
            x: base64url.encode(Buffer.from('53015daa95f69cbd3f431ff5a3b2eefe2bb5d9ea0d296607446aab7b7106f3ed', 'hex'))
        }
        let crypto = new CryptoBuilder()
        .useSigningAlgorithm('EdDSA')
        .build();
        let jsonLdProof: IPayloadProtectionSigning = new JoseBuilder(crypto)
            .uselinkedDataProofsProtocol()
            .build();
        jsonLdProof = jsonLdProof.deserialize(JSON.stringify(doc));
          const result = await (<any>jsonLdProof).verify([publicKey]);
          expect(result).toBeTruthy();
    });
});