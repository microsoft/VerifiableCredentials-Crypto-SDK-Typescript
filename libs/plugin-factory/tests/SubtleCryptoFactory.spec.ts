/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { SubtleCryptoFactory } from '../lib/index';

describe('SubtleCryptoFactory', () => {

  it('should create SubtleCryptoNode', () => {
    const crypto = SubtleCryptoFactory.create('SubtleCryptoNode');
    expect(crypto.constructor.name).toEqual('SubtleCrypto');
  });

});
