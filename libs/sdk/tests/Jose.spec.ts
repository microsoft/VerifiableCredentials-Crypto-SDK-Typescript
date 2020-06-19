/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { ClientSecretCredential } from '@azure/identity';
import { JoseBuilder, CryptoBuilder, IPayloadProtectionSigning, CryptographicKey, ProtectionFormat, Jose, KeyUse, KeyStoreOptions, JsonWebKey } from '../lib/index';
import Credentials from './Credentials';

describe('Jose', () => {

    let originalTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
    beforeEach(async () => {
        jasmine.DEFAULT_TIMEOUT_INTERVAL = 60000;
    });

    afterEach(() => {
        jasmine.DEFAULT_TIMEOUT_INTERVAL = originalTimeout;
    });
    const cryptoNode = new CryptoBuilder()
        .useSigningKeyReference('neo', new KeyStoreOptions({ extractable: true }))
        .build();

    // Loop through these crypto factories. If no credentials for Key Vault are present, we skip key vault
    let factories = [cryptoNode];
    //const alg = { name: 'ECDSA', namedCurve: 'secp256k1', hash: { name: 'SHA-256' } };
            
    if (Credentials.vaultUri.startsWith('https')) {
        const credentials = new ClientSecretCredential(Credentials.tenantGuid, Credentials.clientId, Credentials.clientSecret);

        const cryptoKeyVault = new CryptoBuilder()
            .useKeyVault(credentials, Credentials.vaultUri)
            .useSigningKeyReference('neo')
            .build();
        factories= [cryptoKeyVault, cryptoNode];
    }

    it('should create a builder', () => {
        const crypto = new CryptoBuilder().build();
        const builder = new JoseBuilder(crypto);
        const jose = builder.build();
        expect(jose.builder.crypto).toEqual(crypto);
        expect(jose.builder.jwtProtocol).toBeUndefined();
        expect(jose.builder.protectedHeader).toEqual({});
        expect(jose.builder.unprotectedHeader).toEqual({});
        expect(jose.builder.protocol).toEqual('JOSE');
        expect(jose.builder.serializationFormat).toEqual('JwsCompactJson');
        expect(jose.constructor.name).toEqual('Jose');

    });
    
    it('should sign and verify', async () => {
        const payload = Buffer.from('The only way you can survive is to spread to another area. There is another organism on this planet that follows the same pattern. Do you know what it is? A virus. Human beings are a disease. A cancer of this planet.');

        for (let inx = 0; inx < factories.length; inx++) {
            let crypto = factories[inx];
            console.log(`Using crypto ${crypto.builder.cryptoFactory.constructor.name}`);

            // Generate and save a signing key
            crypto = await crypto.generateKey(KeyUse.Signature);

            let jose: IPayloadProtectionSigning = new JoseBuilder(crypto)
                .build();

            jose = await jose.sign(payload);

            const jwkPublic = (await crypto.builder.keyStore.get('neo', new KeyStoreOptions({publicKeyOnly: true}))).getKey<JsonWebKey>();

            const validated = await jose.verify([jwkPublic]);
            expect(validated).toBeTruthy();

            // negative cases
            // verify has no token
            jose = new JoseBuilder(crypto).build();
            let throwed = false;
            try {
                await jose.verify([jwkPublic]);
            } catch (ex) {
                throwed = true;
                expect(ex).toEqual('Import a token by deserialize');
            }
            expect(throwed).toBeTruthy();

            // serialize has no token
            jose = new JoseBuilder(crypto).build();
            expect(() => jose.serialize()).toThrowError('No token to serialize');

        }


    });

    it('should check ProtectionFormat', () => {
        expect(Jose.getProtectionFormat('jwsflatjson')).toEqual(ProtectionFormat.JwsFlatJson);
        expect(Jose.getProtectionFormat('JwsCompactJson')).toEqual(ProtectionFormat.JwsCompactJson);
        expect(Jose.getProtectionFormat('JwsGeneralJson')).toEqual(ProtectionFormat.JwsGeneralJson);
        expect(Jose.getProtectionFormat('JweFlatJson')).toEqual(ProtectionFormat.JweFlatJson);
        expect(Jose.getProtectionFormat('JweCompactJson')).toEqual(ProtectionFormat.JweCompactJson);
        expect(Jose.getProtectionFormat('JweGeneralJson')).toEqual(ProtectionFormat.JweGeneralJson);
        expect(() => Jose.getProtectionFormat('xxx')).toThrowError(`Format 'xxx' is not supported`);
    });
});