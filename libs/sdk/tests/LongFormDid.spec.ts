/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { CryptoBuilder, CryptoFactory, KeyStoreFactory, Subtle, KeyUse, KeyStoreOptions, KeyReference, LongFormDid } from '../lib/index';

describe('LongFormDid', () => {
    it('should generate a longform DID', async () =>{
        let crypto = new CryptoBuilder()
            .useSigningKeyReference(new KeyReference('mars'))
            .useRecoveryKeyReference(new KeyReference('recovery'))
            .build();
        crypto = await crypto.generateKey(KeyUse.Signature);
        crypto = await crypto.generateKey(KeyUse.Signature, 'recovery');

        let did = await new LongFormDid(crypto).serialize();
        expect(did.startsWith('did:ion')).toBeTruthy();
        console.log(did);
     });
});
