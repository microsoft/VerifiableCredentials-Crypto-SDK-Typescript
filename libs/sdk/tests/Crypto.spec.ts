/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { CryptoBuilder, Crypto, KeyUse, KeyReference, JoseBuilder, Subtle } from '../lib/index';

describe('Crypto', () => {
    it('should generate a signing key', async () => {
        let crypto = new CryptoBuilder()
            .useSigningKeyReference(new KeyReference('mars'))
            .useRecoveryKeyReference(new KeyReference('recovery'))
            .build();
        expect(crypto.builder.recoveryKeyReference).toEqual(new KeyReference('recovery'));
        expect(crypto.signingProtocol(JoseBuilder.JOSE).constructor.name).toEqual('Jose');

        crypto = await crypto.generateKey(KeyUse.Signature);
        expect(crypto.builder.signingKeyReference?.cryptoKey).toBeDefined();

        // Negative cases
    });

    it('should generate a recovery key', async () => {
        let crypto = new CryptoBuilder()
            .useSigningKeyReference(new KeyReference('mars'))
            .useRecoveryKeyReference(new KeyReference('recovery'))
            .build();
        expect(crypto.builder.recoveryKeyReference).toEqual(new KeyReference('recovery'));

        crypto = await crypto.generateKey(KeyUse.Signature, 'recovery');
        expect(crypto.builder.recoveryKeyReference?.cryptoKey).toBeDefined();

        // negative cases
        let throwed = false;
        await crypto.generateKey(KeyUse.Signature, 'test')
            .catch((exception) => {
                expect(exception.message).toEqual(`Key generation type 'test' not supported`);
                throwed = true;
            })
        expect(throwed).toBeTruthy();

        try {
            await crypto.generateKey(KeyUse.Encryption);
        } catch (exception) {
            expect(exception.message).toEqual('not implemented');
        }
    });
});