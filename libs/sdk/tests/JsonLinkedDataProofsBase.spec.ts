/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { CryptoBuilder, JoseBuilder, JsonLinkedDataProofsBase } from '../lib';

describe('JsonLinkedDataProofsBase', () => {
    it('should instantiate JsonLinkedDataProofsBase', async () => {
        let crypto = new CryptoBuilder()
        .useSigningAlgorithm('EdDSA')
        .build();
        const jsonLdProofs = new JoseBuilder(crypto)
            .build();

        const jsonLdBase = new JsonLinkedDataProofsBase(jsonLdProofs);
        expect(jsonLdBase.type).toEqual('');
        expect(jsonLdBase.alg).toEqual('');
        try {
            await jsonLdBase.sign({});
            fail('should throw ' + 'sign not implemented')
        } catch (error) {
            expect(error).toEqual('sign not implemented')
        }

        try {
            await jsonLdBase.verify([]);
            fail('should throw ' + 'verify not implemented')
        } catch (error) {
            expect(error).toEqual('verify not implemented')
        }

        try {
            await jsonLdBase.serialize();
            fail('should throw ' + 'No credential to serialize')
        } catch (error) {
            expect(error).toEqual('No credential to serialize')
        }

        try {
            await jsonLdBase.deserialize('xxx');
            fail('should throw ' + 'Could not parse JSON LD token')
        } catch (error) {
            expect(error).toEqual('Could not parse JSON LD token')
        }
    });
});