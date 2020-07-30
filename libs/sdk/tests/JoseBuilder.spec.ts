/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { JoseBuilder, CryptoBuilder } from '../lib/index';

describe('JoseBuilder', () => {
    it ('should create a builder', () =>{
        const crypto = new CryptoBuilder().build();
        let builder = new JoseBuilder(crypto);
        expect(builder.crypto).toEqual(crypto);
        expect(builder.jwtProtocol).toBeUndefined();
        let header = {typ: 'JWT'};
        expect(builder.protectedHeader).toEqual(header);
        expect(builder.unprotectedHeader).toEqual({});
        expect(builder.protocol).toEqual('JOSE');
        expect(builder.serializationFormat).toEqual('JwsCompactJson');

        builder  = builder.useJwtProtocol({});
        expect(builder.protocol).toEqual('JWT');

        const protectedHeader = {typ: 'JWT'};
        builder = builder.useProtectedHeader(protectedHeader)
        expect(builder.protectedHeader).toEqual(protectedHeader);
        const unprotectedHeader = {test: 'JWT'};
        builder = builder.useUnprotectedHeader(unprotectedHeader)
        expect(builder.unprotectedHeader).toEqual(unprotectedHeader);
        
        builder = builder.useSerializationFormat('someprotocol');
        expect(builder.serializationFormat).toEqual('someprotocol');      
        
    });
});