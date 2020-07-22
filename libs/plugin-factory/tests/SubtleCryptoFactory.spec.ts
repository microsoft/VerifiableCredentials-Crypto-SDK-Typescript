/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { SubtleCryptoFactory } from '../lib/index';
import { ClientSecretCredential } from '@azure/identity';
import Credentials from './Credentials';
import { KeyStoreKeyVault } from 'verifiablecredentials-crypto-sdk-typescript-plugin-keyvault';
import { KeyStoreInMemory } from 'verifiablecredentials-crypto-sdk-typescript-keystore';

describe('SubtleCryptoFactory', () => {

  it('should create SubtleCryptoNode', () => {
    const crypto = SubtleCryptoFactory.create('SubtleCryptoNode');
    expect(crypto.constructor.name).toEqual('Subtle');

    // negative cases
    expect(() => SubtleCryptoFactory.create('xxx')).toThrowError(`Subtle crypto 'xxx' not found`)
  });

  it('should create SubtleCryptoKeyVault', () => {

    // Sample config
    const tenantId = Credentials.tenantGuid;
    const clientId = Credentials.clientId;
    const clientSecret = encodeURI(Credentials.clientSecret);
    const vaultUri = Credentials.vaultUri;

    const subtle = SubtleCryptoFactory.create('SubtleCryptoNode');
    const cache = new KeyStoreInMemory();

    const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
    const keyStore = new KeyStoreKeyVault(credential, vaultUri, cache);

    const crypto = SubtleCryptoFactory.create('SubtleCryptoKeyVault', credential, vaultUri);
    expect(crypto.constructor.name).toEqual('SubtleCryptoKeyVault');
  });

  it('should create key in keyvault', () => {

    // Sample config
    const tenantId = Credentials.tenantGuid;
    const clientId = Credentials.clientId;
    const clientSecret = encodeURI(Credentials.clientSecret);
    const vaultUri = Credentials.vaultUri;

    const subtle = SubtleCryptoFactory.create('SubtleCryptoNode');
    const cache = new KeyStoreInMemory();

    const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
    const keyStore = new KeyStoreKeyVault(credential, vaultUri, cache);

    const crypto = SubtleCryptoFactory.create('SubtleCryptoKeyVault', credential, vaultUri);
    expect(crypto.constructor.name).toEqual('SubtleCryptoKeyVault');
  });


});
