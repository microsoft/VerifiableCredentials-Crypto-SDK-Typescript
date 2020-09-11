import { Crypto, CryptoBuilder, KeyUse, JoseBuilder, IPayloadProtectionSigning, CryptoFactoryNode, KeyStoreInMemory, Subtle } from '../lib/index';

describe('JWT', () => {
    it('should add standard props', async () => {
        let crypto = new CryptoBuilder()
            .useCryptoFactory(new CryptoFactoryNode(new KeyStoreInMemory(), new Subtle()))
            .useSigningAlgorithm('EdDSA')
            .build();
        crypto = await crypto.generateKey(KeyUse.Signature);

        let jwt: IPayloadProtectionSigning = new JoseBuilder(crypto)
            .useJwtProtocol({})
            .build();

        const payload = { message: 'Hello Houston' };
        jwt = await jwt.sign(payload);
        const token = jwt.serialize();
        const signedPayload = JSON.parse((<any>jwt.deserialize(token))._signaturePayload.toString());
        expect(signedPayload.exp).toBeDefined();
        expect(signedPayload.nbf).toBeDefined();
        expect(signedPayload.jti).toBeDefined();
    });
});