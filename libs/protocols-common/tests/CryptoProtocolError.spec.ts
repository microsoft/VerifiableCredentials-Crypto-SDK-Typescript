/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { CryptoProtocolError } from '../lib/index';

 describe('CryptoProtocolError', () => {
    it('should create CryptoProtocolError', () => {
        const error = new CryptoProtocolError('ecdsa', 'error in EC');
        expect(error.protocol).toEqual('ecdsa');
        expect(error.message).toEqual('error in EC');
    })
 });