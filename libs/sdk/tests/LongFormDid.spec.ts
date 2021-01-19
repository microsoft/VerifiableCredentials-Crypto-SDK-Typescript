/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { CryptoBuilder, CryptoFactory, KeyStoreFactory, Subtle, KeyUse, KeyStoreOptions, KeyReference, LongFormDid } from '../lib/index';

describe('LongFormDid', () => {
    it('should generate a longform DID', async () => {
        let crypto = new CryptoBuilder()
            .useSigningKeyReference(new KeyReference('mars'))
            .useRecoveryKeyReference(new KeyReference('recovery'))
            .useUpdateKeyReference(new KeyReference('update'))
            .build();
        crypto = await crypto.generateKey(KeyUse.Signature);
        crypto = await crypto.generateKey(KeyUse.Signature, 'recovery');
        crypto = await crypto.generateKey(KeyUse.Signature, 'update');

        const jwk = await crypto.builder.keyStore.get(crypto.builder.signingKeyReference);
        console.log(JSON.stringify(jwk));

        let did = await new LongFormDid(crypto).serialize();
        expect(did.startsWith('did:ion')).toBeTruthy();
        console.log(did);

        // negative cases

        // missing keys
        crypto = new CryptoBuilder()
            .useSigningKeyReference(new KeyReference('mars'))
            .useRecoveryKeyReference(new KeyReference('recovery'))
            .useUpdateKeyReference(new KeyReference('update'))
            .build();
        try {
            await new LongFormDid(crypto).serialize();
            fail('missing signing key should fail');
        } catch (exception) {
            expect(exception.message).toEqual('mars not found');
        }
        crypto = await crypto.generateKey(KeyUse.Signature);
        try {
            await new LongFormDid(crypto).serialize();
            fail('missing recovery key should fail');
        } catch (exception) {
            expect(exception.message).toEqual('recovery not found');
        }
        crypto = await crypto.generateKey(KeyUse.Signature, 'recovery');
        try {
            await new LongFormDid(crypto).serialize();
            fail('missing update key should fail');
        } catch (exception) {
            expect(exception.message).toEqual('update not found');
        }

        // wrong key algos
        crypto = new CryptoBuilder()
            .useUpdateAlgorithm('EdDSA')
            .build();
        let longform = new LongFormDid(crypto);
        try {
            await longform.serialize();
            fail('wrong update key algorithm should fail');
        } catch (exception) {
            expect(exception.message).toEqual('Longform DIDs only support ES256K. Update algorithm: EdDSA');
        }
        crypto = new CryptoBuilder()
            .useRecoveryAlgorithm('EdDSA')
            .build();
        longform = new LongFormDid(crypto);
        try {
            await longform.serialize();
            fail('wrong recovery key algorithm should fail');
        } catch (exception) {
            expect(exception.message).toEqual('Longform DIDs only support ES256K. Recovery algorithm: EdDSA');
        }
        crypto = new CryptoBuilder()
            .useSigningAlgorithm('EdDSA')
            .build();
        longform = new LongFormDid(crypto);
        try {
            await longform.serialize();
            fail('wrong signing key algorithm should fail');
        } catch (exception) {
            expect(exception.message).toEqual('Longform DIDs only support ES256K. Signing algorithm: EdDSA');
        }

    });
    it('should add services to the longform DID', async () => {
        let crypto = new CryptoBuilder()
            .useSigningKeyReference(new KeyReference('mars'))
            .useRecoveryKeyReference(new KeyReference('recovery'))
            .useUpdateKeyReference(new KeyReference('update'))
            .build();
        crypto = await crypto.generateKey(KeyUse.Signature);
        crypto = await crypto.generateKey(KeyUse.Signature, 'recovery');
        crypto = await crypto.generateKey(KeyUse.Signature, 'update');

        let did1 = await new LongFormDid(crypto).serialize();
        let did2 = await new LongFormDid(crypto).serialize();
        expect(did1).toEqual(did2);
        const services = {
            id: "service1Id",
            type: "service1Type",
            serviceEndpoint: "http://www.service1.com"
          }
        did2 = await new LongFormDid(crypto, [services]).serialize();
        expect(did1).not.toEqual(did2);
    });
});
