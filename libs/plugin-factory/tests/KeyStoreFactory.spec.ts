/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { ClientSecretCredential } from '@azure/identity';
import KeyStoreFactory from '../lib/KeyStoreFactory';
import { IKeyStore } from 'verifiablecredentials-crypto-sdk-typescript-keystore';

// Sample config
const tenantId = '72f988bf-86f1-41af-91ab-2d7cd011db47';
const clientId = '7fa8fc75-9416-4f21-8b50-0a28e88e8b98';
const clientSecret = encodeURI('qG7u3c4mlCq+tsSXNtL?oTgPO@2uC*oc');
const vaultUri = 'https://did-keyvault-testing.vault.azure.net/';

describe('KeyStoreFactory', () => {
  it('should create the key store in memory', () => {
    const keyStore: IKeyStore = KeyStoreFactory.create('KeyStoreInMemory');
    expect(keyStore.constructor.name).toEqual('KeyStoreInMemory');
    
    // negative cases
    expect(() => KeyStoreFactory.create('xxx')).toThrowError(`Key store 'xxx' not found`);
  });
  it('should create the KV key store', () => {
    const credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
    let keyStore: IKeyStore = KeyStoreFactory.create('KeyStoreKeyVault', credential, vaultUri);
    expect(keyStore.constructor.name).toEqual('KeyStoreKeyVault');
    keyStore = KeyStoreFactory.create('KeyStoreKeyVault', credential, vaultUri, keyStore);
    expect(keyStore.constructor.name).toEqual('KeyStoreKeyVault');
  });
});
