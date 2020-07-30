/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { CryptoBuilder, KeyUse, KeyReference } from '../lib/index';

describe('Crypto', () => {
    it('should generate a signing key', async () => {
        let crypto = new CryptoBuilder()
            .useSigningKeyReference(new KeyReference('mars'))
            .useRecoveryKeyReference(new KeyReference('recovery'))
            .build();
        expect(crypto.builder.recoveryKeyReference).toEqual(new KeyReference('recovery'));
        expect(crypto.signingProtocol.constructor.name).toEqual('Jose');

        crypto = await crypto.generateKey(KeyUse.Signature);
        expect(crypto.builder.signingKeyReference?.cryptoKey).toBeDefined();

        // negative cases
        let throwed = false;
        await crypto.generateKey(KeyUse.Encryption)
            .catch((e) => {
                expect(e.message).toEqual(`not implemented`);
                throwed = true;
            })
        expect(throwed).toBeTruthy();

        crypto = new CryptoBuilder()
            .useRecoveryKeyReference(new KeyReference('recovery'))
            .build();

        throwed = false;
        await crypto.generateKey(KeyUse.Signature)
            .catch((e) => {
                expect(e.message).toEqual(`signingKeyReference is not defined in crypto`);
                throwed = true;
            })
        expect(throwed).toBeTruthy();
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
            .catch((e) => {
                expect(e.message).toEqual(`Key generation type 'test' not supported`);
                throwed = true;
            })
        expect(throwed).toBeTruthy();

        crypto = new CryptoBuilder()
            .useSigningKeyReference(new KeyReference('signing'))
            .build();
        throwed = false;
        await crypto.generateKey(KeyUse.Signature, 'recovery')
            .catch((e) => {
                expect(e.message).toEqual(`recoveryKeyReference is not defined in crypto`);
                throwed = true;
            })
        expect(throwed).toBeTruthy();
    });
});