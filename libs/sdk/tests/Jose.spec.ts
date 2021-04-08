/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { ClientSecretCredential } from '@azure/identity';
import { JoseBuilder, Crypto, CryptoBuilder, IPayloadProtectionSigning, CryptographicKey, ProtectionFormat, Jose, KeyUse, KeyStoreOptions, JsonWebKey, KeyReference, KeyStoreKeyVault } from '../lib/index';
import { KeyClient } from '@azure/keyvault-keys';
import Credentials from './Credentials';

describe('Jose', () => {
    const random = (length: number) => Math.random().toString(36).substring(2, length + 2);

    let originalTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
    beforeEach(async () => {
        jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000000;
    });

    afterEach(() => {
        jasmine.DEFAULT_TIMEOUT_INTERVAL = originalTimeout;
    });
    const cryptoNode = new CryptoBuilder()
        .useSigningKeyReference(new KeyReference('neo'))
        .useDid('did')
        .build();

    // Loop through these crypto factories. If no credentials for Key Vault are present, we skip key vault
    let factories = [cryptoNode];
    let cryptoKeyVault: Crypto | undefined;

    //const alg = { name: 'ECDSA', namedCurve: 'secp256k1', hash: { name: 'SHA-256' } };

    if (Credentials.vaultUri.startsWith('https')) {
        const credentials = new ClientSecretCredential(Credentials.tenantGuid, Credentials.clientId, Credentials.clientSecret);
        const remote = 'remote-neo';
        cryptoKeyVault = new CryptoBuilder()
            .useKeyVault(credentials, Credentials.vaultUri)
            .useSigningKeyReference(new KeyReference('neo', 'key', remote))
            .useDid('did')
            .build();
        factories = [cryptoKeyVault, cryptoNode];
    } else {
        console.log('Enter your key vault credentials in Credentials.ts to enable key vault testing')
    }

    it('should create a builder', () => {
        const crypto = new CryptoBuilder().build();
        const builder = new JoseBuilder(crypto);
        const jose = builder.build();
        expect(jose.builder.crypto).toEqual(crypto);
        expect(jose.builder.jwtProtocol).toBeUndefined();
        expect(jose.builder.protectedHeader).toEqual({ typ: 'JWT' });
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

            // Check kid
            let serialized = jose.serialize();
            jose = jose.deserialize(serialized);
            expect(jose.signatureProtectedHeader['typ']).toEqual('JWT');
            expect(jose.signatureProtectedHeader.alg).toEqual('ES256K');
            expect(jose.signatureProtectedHeader.kid).toEqual('did#neo');

            jose = (<Jose>jose).builder
                .useKid('kid')
                .build();

            expect((<Jose>jose).builder.kid).toEqual('kid');
            jose = await jose.sign(payload);
            serialized = jose.serialize();
            jose = jose.deserialize(serialized);
            expect(jose.signatureProtectedHeader!.typ).toEqual('JWT');
            expect(jose.signatureProtectedHeader!.alg).toEqual('ES256K');
            expect(jose.signatureProtectedHeader!.kid).toEqual('kid');

            const jwkPublic = (await crypto.builder.keyStore.get(crypto.builder.signingKeyReference!, new KeyStoreOptions({ publicKeyOnly: true }))).getKey<JsonWebKey>();

            const validated = await jose.verify([jwkPublic]);
            expect(validated).toBeTruthy();

            // negative cases
            jose = (<Jose>jose).builder
                .useSerializationFormat('whatever')
                .build();

            try {
                jose.serialize();
                fail('serializationFormat should fail');
            } catch (e) {
                expect(e.message).toEqual(`Format 'whatever' is not supported`)
            }
            try {
                jose.deserialize(serialized);
                fail('deserializationFormat should fail');
            } catch (e) {
                expect(e.message).toEqual(`Format 'whatever' is not supported`)
            }

            // verify has no token
            jose = new JoseBuilder(crypto).build();
            try {
                await jose.verify([jwkPublic]);
                fail('no token should fail');
            } catch (ex) {
                expect(ex.message).toEqual('Import a token by deserialize');
            }

            // serialize has no token
            jose = new JoseBuilder(crypto).build();
            try {
                jose.serialize();
                fail('no token to serialize should fail');
            } catch (ex) {
                expect(ex.message).toEqual('No token to serialize');
            }
        }
    });


    it('should sign and verify with JWT protocol', async () => {
        const payload = {
            firstName: 'Jules',
            lastName: 'Winnfield'
        };

        let crypto = cryptoNode;

        // Generate and save a signing key
        crypto = await crypto.generateKey(KeyUse.Signature);

        let jose: IPayloadProtectionSigning = new JoseBuilder(crypto)
            .useJwtProtocol({ someProp: 1, jti: 'abc', exp: 1 })
            .useUnprotectedHeader({ my: 'header' })
            .build();

        jose = await jose.sign(payload);

        // Check kid
        let serialized = jose.serialize();
        jose = jose.deserialize(serialized);
        expect(jose.signatureProtectedHeader['typ']).toEqual('JWT');
        expect(jose.signatureProtectedHeader.alg).toEqual('ES256K');
        expect(jose.signatureProtectedHeader.kid).toEqual('did#neo');
        let signedPayload: any = JSON.parse(jose.signaturePayload!.toString('utf-8'));
        expect(signedPayload.someProp).toEqual(1);
        expect(signedPayload.jti).toEqual('abc');
        expect(signedPayload.exp).toEqual(1);
        expect(signedPayload.nbf).toBeDefined();
        expect(jose.signatureHeader).toBeDefined();

        try {
            await jose.sign(Buffer.from(JSON.stringify(payload)));
            fail('Should have throwed exception');
        } catch (exception) {
            expect(exception.message).toEqual('Input to sign JWT must be an object');
        }

        // Negative cases
        try {
            spyOn(Jose, 'getProtectionFormat').and.returnValue(undefined);
            jose.deserialize(serialized);
            fail(`Serialization format 'JwsCompactJson' is not supported should fail`);
        } catch (ex) {
            expect(ex.message).toEqual(`Serialization format 'JwsCompactJson' is not supported`);
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


    it('should check key vault performance', async () => {

        const name = 'KvTest-Jose-performanceTest';
        if (!cryptoKeyVault) {
            console.log('Key vault is enabled. Add your credentials to Credentials.ts')
            return;
        }
        const keyReference = new KeyReference(name, 'key');

        try {
            for (let inx = 0; inx < 10; inx++) {
                const credentials = new ClientSecretCredential(Credentials.tenantGuid, Credentials.clientId, Credentials.clientSecret);
                cryptoKeyVault = new CryptoBuilder()
                    .useKeyVault(credentials, Credentials.vaultUri)
                    .useSigningKeyReference(keyReference)
                    .build();

                let jose: IPayloadProtectionSigning = new JoseBuilder(cryptoKeyVault!).build();
                //await cryptoKeyVault.generateKey(KeyUse.Signature);
                let timer = Math.trunc(Date.now());
                /*
                console.log(`Iteration -----------> ${inx}. Start get timer: ${timer}`);
                const key = await (await cryptoKeyVault!.builder.keyStore.get(new KeyReference(name, 'key)'), new KeyStoreOptions({ publicKeyOnly: true }))).getKey<JsonWebKey>();
                const algorithm = <any>{
                    name: 'ECDSA',
                    namedCurve: 'secp256k1',
                    kid: key.kid
                };
                //keyReference.cryptoKey = await cryptoKeyVault.builder.subtle.importKey('jwk', key, algorithm, true, ['sign', 'verify']);
                
                console.log(`Timer after get: ${Math.trunc(Date.now()) - timer} milliseconds`);
                console.log(`Key: ${JSON.stringify(key)}`);
                */
                console.log(`Iteration -----------> ${inx}. Start sign timer: ${timer}`);
                jose = await cryptoKeyVault!.signingProtocol('JWT').sign({ data: 'Go quick' });
                console.log(`Timer after sign: ${Math.trunc(Date.now()) - timer} milliseconds`);
            }

        } finally {
            //await (<KeyClient>(<KeyStoreKeyVault>cryptoKeyVault.builder.keyStore).getKeyStoreClient('key')).beginDeleteKey(name);
        }
    });

});