/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
 
import { KeyStoreOptions } from '../lib/index';

describe('KeyStoreOptions', () => {

  it('should set the options', async () => {
    let options = new KeyStoreOptions();
    expect(options.latestVersion).toBeTruthy();
    expect(options.publicKeyOnly).toBeTruthy();
    
    options = new KeyStoreOptions({extractable: false});
    expect(options.latestVersion).toBeTruthy();
    expect(options.publicKeyOnly).toBeTruthy();
    
    options = new KeyStoreOptions({latestVersion: false});
    expect(options.latestVersion).toBeFalsy();
    expect(options.publicKeyOnly).toBeTruthy();
    
    options = new KeyStoreOptions({publicKeyOnly: false});
    expect(options.latestVersion).toBeTruthy();
    expect(options.publicKeyOnly).toBeFalsy();
    
    options = new KeyStoreOptions({extractable: false, latestVersion: false});
    expect(options.latestVersion).toBeFalsy();
    expect(options.publicKeyOnly).toBeTruthy();
    
    options = new KeyStoreOptions({extractable: false, latestVersion: true});
    expect(options.latestVersion).toBeTruthy();
    expect(options.publicKeyOnly).toBeTruthy();

    options = new KeyStoreOptions({extractable: false, latestVersion: true, publicKeyOnly: false});
    expect(options.latestVersion).toBeTruthy();
    expect(options.publicKeyOnly).toBeFalsy();

    options = new KeyStoreOptions({extractable: true, latestVersion: true, publicKeyOnly: false});
    expect(options.latestVersion).toBeTruthy();
    expect(options.publicKeyOnly).toBeFalsy();

    options = new KeyStoreOptions({extractable: true, latestVersion: true, publicKeyOnly: true});
    expect(options.latestVersion).toBeTruthy();
    expect(options.publicKeyOnly).toBeTruthy();

    options = new KeyStoreOptions({extractable: false, latestVersion: false, publicKeyOnly: false});
    expect(options.latestVersion).toBeFalsy();
    expect(options.publicKeyOnly).toBeFalsy();
  });
});
