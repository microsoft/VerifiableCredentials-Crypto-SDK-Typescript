/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { CryptoBuilder, KeyUse, JoseBuilder, IPayloadProtectionSigning, CryptoFactoryNode, KeyStoreInMemory, Subtle, LongFormDid } from '../lib/index';

describe('JSONLD proofs', () => {
    fit('should sign a credential', async () => {
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
    });
});