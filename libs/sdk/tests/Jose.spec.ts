/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { JoseBuilder, CryptoBuilder, IPayloadProtectionSigning, CryptographicKey, ProtectionFormat, Jose } from '../lib/index';

describe('Jose', () => {
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

        // Generate and save a signing key
        const crypto = new CryptoBuilder()
            .useSigningKeyReference('neo')
            .build();

        const alg = { name: 'ECDSA', namedCurve: 'secp256k1', hash: { name: 'SHA-256' } };
        const keyPair = <CryptoKeyPair>await crypto.builder.subtle.generateKey(alg, true, ['sign', 'verify']);
        const jwkPrivate = await crypto.builder.subtle.exportKey('jwk', keyPair.privateKey);
        await crypto.builder.keyStore.save(crypto.builder.signingKeyReference!, <CryptographicKey>jwkPrivate);

        let jose: IPayloadProtectionSigning = new JoseBuilder(crypto)
            .build();

        jose = await jose.sign(payload);
        const jwkPublic = <CryptographicKey>await crypto.builder.subtle.exportKey('jwk', keyPair.publicKey);

        expect(await jose.verify([jwkPublic])).toBeTruthy();

        // import the signature to validate
        const token = jose.serialize();
        jose = new JoseBuilder(crypto).build();
        jose = jose.deserialize(token);
        expect(await jose.verify([jwkPublic])).toBeTruthy();

        // negative cases
        // verify has no token
        jose = new JoseBuilder(crypto).build();
        let throwed = false;
        try {
            await jose.verify([jwkPublic]);
        } catch(ex) {
            throwed = true;
            expect(ex).toEqual('Import a token by deserialize');
        }
        expect(throwed).toBeTruthy();

        // serialize has no token
        jose = new JoseBuilder(crypto).build();
        expect(() => jose.serialize()).toThrowError('No token to serialize');
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