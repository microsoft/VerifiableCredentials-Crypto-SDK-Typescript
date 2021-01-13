import { TSMap } from "typescript-map";
import { JoseConstants } from "verifiablecredentials-crypto-sdk-typescript-keys";
import { KeyStoreInMemory } from "verifiablecredentials-crypto-sdk-typescript-keystore";
import { CryptoFactory, SubtleCryptoNode } from "verifiablecredentials-crypto-sdk-typescript-plugin";
import { IPayloadProtectionOptions } from "verifiablecredentials-crypto-sdk-typescript-protocols-common";
import { JoseProtocol, JoseToken } from "../lib";

describe('JoseToken', () => {
    const keyStore = new KeyStoreInMemory();
    const cryptoFactory = new CryptoFactory(keyStore, SubtleCryptoNode.getSubtleCrypto())
    const options: IPayloadProtectionOptions = {
      cryptoFactory,
      options: new TSMap<string, any>([
        [JoseConstants.optionProtectedHeader, new TSMap([['typ', 'JWT']])]
      ]),
      payloadProtection: new JoseProtocol()
    };

    it('should instantiate a token', () => {
        let token = new JoseToken(options);
        expect(() => token.tokenFormat()).toThrowError('The token format is not found');

        token.set(JoseConstants.tokenFormat, 'JwsCompactJson');
        expect(token.tokenFormat()).toEqual('JwsCompactJson');
    })
});