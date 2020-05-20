/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { ProviderCrypto } from 'webcrypto-core';

/**
 * Wrapper class to integrate elliptic into web crypto
 */
export default abstract class EllipticDsaProvider extends ProviderCrypto {

  /**
   * Different usages supported by the provider
   */
  public usages: any = {
    privateKey: ['sign'],
    publicKey: ['verify']
  };

  constructor ( _subtle: any) {
    super();
  }

  /**
   * Get the instance that implements the algorithm
   * @param name Name of the algorithm
   */
  abstract getCurve(name: string): any;

  /**
   * format the signature output from DER format
   * @param signature to decode from DER
   */
   public static fromDer(signature: Uint8Array): Uint8Array[] {
    if (signature[0] !== 0x30) {
      throw new Error('No DER format to decode');
    }

    const lengthOfRemaining = signature[1];
    const results: Uint8Array[] = [];
    let index: number = 2;
    while (index < lengthOfRemaining) {
      const marker = signature[index++];
      if (marker !== 0x02) {
        throw new Error(`Marker on index ${index-1} must be 0x02`);
      }

      let length = signature[index++];
      while (signature[index] === 0) {
        index ++;
        length --;
      }
      const data = signature.slice(index, index + length);
      results.push(data);
      index = index + length;
    }
    return results;
  }

  /**
   * format the signature output to DER format
   * @param elements Array of elements to encode in DER
   */
  public static toDer(elements: ArrayBuffer[]): ArrayBuffer {
    let index: number = 0;
    // calculate total size. 
    let lengthOfRemaining = 0;
    for (let element = 0 ; element < elements.length; element++) {
      // Add element format bytes
      lengthOfRemaining += 2;
      const buffer = new Uint8Array(elements[element]);
      const size = (buffer[0] & 0x80) === 0x80 ? buffer.length + 1 : buffer.length;
      lengthOfRemaining += size;
    }
    // Prepare output
    index = 0;
    const result = new Uint8Array(lengthOfRemaining + 2);
    result.set([0x30, lengthOfRemaining], index);
    index += 2;
    for (let element = 0 ; element < elements.length; element++) {
      // Add element format bytes
      const buffer = new Uint8Array(elements[element]);
      const size = (buffer[0] & 0x80) === 0x80 ? buffer.length + 1 : buffer.length;
      result.set([0x02, size], index);
      index += 2;
      if (size > buffer.length) {
        result.set([0x0], index++);
      }
      
      result.set(buffer, index);
      index += buffer.length;
    }

    return result;
  }
}
