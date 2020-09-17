/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { CryptoBuilder, KeyUse, JoseBuilder, IPayloadProtectionSigning, CryptoFactoryNode, KeyStoreInMemory, Subtle, LongFormDid, KeyStoreOptions } from '../lib/index';
import { PublicKey } from 'verifiablecredentials-crypto-sdk-typescript-keys';
import base64url from 'base64url';

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
            .useCryptoFactory(new CryptoFactoryNode(new KeyStoreInMemory(), new Subtle()))
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
        console.log(jsonLdProof);
        const publicKey = await (await crypto.builder.keyStore.get(crypto.builder.signingKeyReference, new KeyStoreOptions({ publicKeyOnly: true }))).getKey<PublicKey>();
        expect(await jsonLdProof.verify([publicKey])).toBeTruthy();
    });

    fit('should validate test vectors', async () => {
        const bs58 = require('bs58')

        let b58 = 'dbDmZLTWuEYYZNHFLKLoRkEX4sZykkSLNQLXvMUyMB1'
        let bytes = bs58.decode(b58);
        let b64 = base64url.encode(bytes);
        b58 = '47QbyJEDqmHTzsdg8xzqXD8gqKuLufYRrKWTmB7eAaWHG2EAsQ2GUyqRqWWYT15dGuag52Sf3j4hs2mu7w52mgps'
        bytes = bs58.decode(b58);
        b64 = base64url.encode(bytes);
        console.log(b64);

        const credential = require('./testVectors/credential.json');
        const keypair = require('./testVectors/keypair.json');
        const serialized = JSON.stringify(credential.vc_0);
        let crypto = new CryptoBuilder()
            .useCryptoFactory(new CryptoFactoryNode(new KeyStoreInMemory(), new Subtle()))
            .useSigningAlgorithm('EdDSA')
            .build();
        await crypto.builder.keyStore.save(crypto.builder.signingKeyReference, keypair.keypair_0);
        let jsonLdProof: IPayloadProtectionSigning = new JoseBuilder(crypto)
            .uselinkedDataProofsProtocol()
            .build();
        jsonLdProof = jsonLdProof.deserialize(JSON.stringify(credential.vc_0));
        const publicKey = await (await crypto.builder.keyStore.get(crypto.builder.signingKeyReference, new KeyStoreOptions({ publicKeyOnly: true }))).getKey<PublicKey>();
        const result = await jsonLdProof.verify([publicKey]);
        expect(result).toBeTruthy();
        console.log(serialized);
    });
});