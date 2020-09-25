import { PublicKey } from 'verifiablecredentials-crypto-sdk-typescript-keys';
/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { LongFormDid, CryptoBuilder, IJsonLinkedDataProofSuite, JoseBuilder, KeyUse, KeyStoreOptions } from '../lib';
import SuiteJcsEd25519Signature2020 from '../lib/suites/SuiteJcsEd25519Signature2020';

describe('SuiteJcsEd25519Signature2020', ()=> {
    fit('should sign and verify a payload', async () => {
        let crypto = new CryptoBuilder()
            .useSigningAlgorithm('EdDSA')
            .build();
        crypto = await crypto.generateKey(KeyUse.Signature);
        crypto = await crypto.generateKey(KeyUse.Signature, 'recovery');
        const did = await new LongFormDid(crypto).serialize();
        crypto = crypto.builder.useDid(did).build();

        const jsonLdProofs = new JoseBuilder(crypto)
            .uselinkedDataProofsProtocol({})
            .build();
        
        let suite: IJsonLinkedDataProofSuite = new SuiteJcsEd25519Signature2020(jsonLdProofs);
        let payload = {
            prop1: 'prop1',
            prop2: 'prop2'
        };

        suite = await suite.sign(payload);
        const serialized = await suite.serialize();
        const pl = JSON.parse(serialized);
        expect(pl.proof.signatureValue).toBeDefined();

        // Verify
        suite = await suite.deserialize(serialized);
        const key = (await crypto.builder.keyStore.get(crypto.builder.signingKeyReference, new KeyStoreOptions({publicKeyOnly: true}))).getKey<PublicKey>();
        const result = await suite.verify([key]);
        expect(result).toBeTruthy();
    });
});