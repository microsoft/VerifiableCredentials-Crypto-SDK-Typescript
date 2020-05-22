/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { JoseHelpers } from "../lib/index";
import { CryptoProtocolError } from 'verifiablecredentials-crypto-sdk-typescript-protocols-common';
import { KeyType } from 'verifiablecredentials-crypto-sdk-typescript-keys';
import { TSMap } from 'typescript-map';

describe('JoseHelpers', () => {
  // Disabling the test below to unblock identiverse demo. Refactoring
  // required before we can re-enable or remove.
  it('should return header status from headerHasElements', () => {
    const header = new TSMap<string, string>();
    expect(JoseHelpers.headerHasElements(header)).toBeFalsy();
    // tslint:disable-next-line: no-backbone-get-set-outside-model
    header.set('key', 'value');
    expect(JoseHelpers.headerHasElements(header)).toBeTruthy();
  });

  it('should encode headers', () => {
    const header = new TSMap<string, string>();
    let encoded = JoseHelpers.encodeHeader(header);
    expect(encoded).toEqual('e30');
    encoded = JoseHelpers.encodeHeader(header, false);
    expect(encoded).toEqual('{}');
    // tslint:disable-next-line: no-backbone-get-set-outside-model
    header.set('key', 'value');
    encoded = JoseHelpers.encodeHeader(header);
    expect(encoded).toEqual('eyJrZXkiOiJ2YWx1ZSJ9');
    encoded = JoseHelpers.encodeHeader(header, false);
    expect(encoded).toEqual('{"key":"value"}');
  });

  it('should throw because header element does not exist', () => {
    let throwed = false;
    try {
      JoseHelpers.getOptionsProperty('xxxx', undefined, undefined);
    } catch (err) {
      throwed = true;
      expect(err.message).toBe(`The property 'xxxx' is missing from options`);
      expect(err.constructor === CryptoProtocolError).toBeTruthy();
    }
    expect(throwed).toBeTruthy();
  });
  it(`should return the key type for 'EC' via JWA`, () => {
    expect(JoseHelpers.createTypeViaJwa('ES256K')).toEqual(KeyType.EC);
  });
  
  it(`should return the key type for 'RSA' via JWA`, () => {
    expect(JoseHelpers.createTypeViaJwa('RS256')).toEqual(KeyType.RSA);
  });
  
});
