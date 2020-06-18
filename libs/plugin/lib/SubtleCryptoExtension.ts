/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { CryptoHelpers, PairwiseKey, CryptoFactory, CryptoFactoryScope, Subtle, ISubtleCryptoExtension } from './index';
import { CryptoKey } from 'webcrypto-core';
import { PublicKey, PrivateKey, KeyType, IKeyContainer } from 'verifiablecredentials-crypto-sdk-typescript-keys';
import { KeyReferenceOptions, IKeyStore, CryptoAlgorithm, CryptoError } from 'verifiablecredentials-crypto-sdk-typescript-keystore';

/**
 * The class extends the @class Subtle with addtional methods.
 *  Adds methods to work with key references.
 *  Extends Subtle to work with JWK keys.
 */
export default class SubtleCryptoExtension extends Subtle implements ISubtleCryptoExtension {
  private keyStore: IKeyStore;

  constructor(public cryptoFactory: CryptoFactory) {
    super();
    this.keyStore = cryptoFactory.keyStore;
  }

  /**
   * Generate a pairwise key for the algorithm
   * @param algorithm for the key
   * @param seedReference Reference to the seed
   * @param personaId Id for the persona
   * @param peerId Id for the peer
   * @param extractable True if key is exportable
   * @param keyops Key operations
   */
  public async generatePairwiseKey(algorithm: EcKeyGenParams | RsaHashedKeyGenParams, seedReference: string, personaId: string, peerId: string): Promise<PrivateKey> {
    const pairwiseKey = new PairwiseKey(this.cryptoFactory);
    return pairwiseKey.generatePairwiseKey(algorithm, seedReference, personaId, peerId);
  }

  /**
   * Sign with a key referenced in the key store
   * @param algorithm used for signature
   * @param keyReference points to key in the key store
   * @param data to sign
   * @returns The signature in the requested algorithm
   */
  public async signByKeyStore(algorithm: CryptoAlgorithm, keyReference: string | KeyReferenceOptions, data: BufferSource): Promise<ArrayBuffer> {
    const keyReferenceInStore = typeof keyReference === 'object' ? keyReference.keyReference : keyReference;
    const extractable = typeof keyReference === 'object' ? keyReference.extractable : true;

    let jwk: PrivateKey = (await <Promise<IKeyContainer>>this.keyStore.get(keyReferenceInStore, { publicKeyOnly: false, extractable })).getKey<PrivateKey>();

    const crypto: Subtle = CryptoHelpers.getSubtleCryptoForAlgorithm(this.cryptoFactory, algorithm, CryptoFactoryScope.Private);
    const keyImportAlgorithm: any = CryptoHelpers.getKeyImportAlgorithm(algorithm, jwk);

    const key = await crypto.importKey('jwk', jwk, keyImportAlgorithm, true, ['sign']);
    const signature = await <PromiseLike<ArrayBuffer>>crypto.sign(jwk.kty === KeyType.EC || jwk.kty === KeyType.OKP ? <EcdsaParams>algorithm : <RsaPssParams>algorithm,
      key,
      <ArrayBuffer>data);

    // only applicable for EC algorithms and when no encoding is applied
    const isElliptic = algorithm.name === 'ECDSA' || algorithm.name === 'EDDSA';
    // EDDSA/ECDSA returns two 32 bit values R & S. Some API's will encode these values in DER
    const format: string = (<any>algorithm).format;
    if (isElliptic && signature.byteLength <= 64 && format) {
      if (format.toUpperCase() !== 'DER') {
        throw new CryptoError(algorithm, 'Only DER format supported for signature');
      }

      // DER format needed for signature, specied in algorithm
      const r = signature.slice(0, signature.byteLength / 2);
      const s = signature.slice(signature.byteLength / 2, signature.byteLength)
      return SubtleCryptoExtension.toDer([r, s]);
    }

    if (isElliptic && signature.byteLength > 64 && format) {
      // DER encoded is not requested and signature is DER encoded
      // In this case the encoding is removed and returned as 64 bytes
      const decodedSignature = SubtleCryptoExtension.fromDer(new Uint8Array(signature));
      const signed = new Uint8Array(decodedSignature[0].length + decodedSignature[1].length);
      signed.set(decodedSignature[0]);
      signed.set(decodedSignature[1], decodedSignature[1].length);
      return signed;
    }

    return signature;
  }

  /**
   * format the signature output to DER format
   * @param elements Array of elements to encode in DER
   */
  public static toDer(elements: ArrayBuffer[]): ArrayBuffer {
    const lengthIndex = 1;
    const sequenceBytes = 2;
    const result = new Uint8Array(254);
    result.set([0x30, 0x00], 0);
    let bytesWritten = sequenceBytes;

    for (let element of elements) {
      let buffer = new Uint8Array(element);
      let zeroPadBytes = 0;
      let paddingByteCount = 0;

      // write the length byte and the integer marker
      result.set([0x02, 0x00], bytesWritten++);
      let currentNumberLengthIndex = bytesWritten++;

      // zero padded bytes do not get encoded in DER
      while (buffer[zeroPadBytes] === 0x0) {
        zeroPadBytes++;
      }

      // if the most significant bit is 1, the number must be padded
      if ((buffer[zeroPadBytes] & 0x80) === 0x80) {
        paddingByteCount = 1;
        result.set([0x0], bytesWritten++);
      }

      // don't copy zero pad bytes
      if (zeroPadBytes > 0) {
        buffer = new Uint8Array(buffer.buffer, zeroPadBytes, buffer.length - zeroPadBytes);
      }

      // the length of the resulting buffer plus the paddingByteCount is the encoded length
      result[currentNumberLengthIndex] = buffer.length + paddingByteCount;

      // write the buffer and increment the amount of bytes written
      result.set(buffer, bytesWritten);
      bytesWritten += buffer.length;
    }

    result[lengthIndex] = bytesWritten - sequenceBytes;
    return new Uint8Array(result.buffer, 0, bytesWritten);
  }

  /**
   * Verify with JWK.
   * @param algorithm used for verification
   * @param jwk Json web key used to verify
   * @param signature to verify
   * @param payload which was signed
   */
  public async verifyByJwk(algorithm: CryptoAlgorithm, jwk: JsonWebKey, signature: BufferSource, payload: BufferSource): Promise<boolean> {
    const crypto: Subtle = CryptoHelpers.getSubtleCryptoForAlgorithm(this.cryptoFactory, algorithm, CryptoFactoryScope.Public);
    const keyImportAlgorithm: any = CryptoHelpers.getKeyImportAlgorithm(algorithm, jwk);

    const key = await crypto.importKey('jwk', jwk, keyImportAlgorithm, true, ['verify']);
    const isElliptic = algorithm.name === 'ECDSA' || algorithm.name === 'EDDSA';

    // The underlying signature validation does not support DER encoding so needs to be removed
    if (isElliptic && signature.byteLength > 64) {
      const elements = SubtleCryptoExtension.fromDer(<Uint8Array>signature);
      signature = new Uint8Array(elements[0].length + elements[1].length);
      (<Uint8Array>signature).set(elements[0]);
      (<Uint8Array>signature).set(elements[1], elements[1].length);
    } else {
      signature = new Uint8Array(<Buffer>signature);
    }

    return crypto.verify(isElliptic ?
      algorithm :
      <RsaPssParams>algorithm, key, <ArrayBuffer>signature, <ArrayBuffer>payload);
  }

  /**
   * For some standards, like JWS R||S expects each part to be padded
   * @param value The byte array representing an number
   * @param length The expected length
   */
  public static toPaddedNumber(value: Uint8Array, length: number = 32){
    
    if(value.length >= length){
      return value; 
    }

    var arr = new Uint8Array(length);
    arr.set(value, length - value.length);
    return arr;
  }

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
        throw new Error(`Marker on index ${index - 1} must be 0x02`);
      }

      let length = signature[index++];
      while (signature[index] === 0) {
        index++;
        length--;
      }
      const data = signature.slice(index, index + length);
      results.push(data);
      index = index + length;
    }
    return results;
  }

  /**
   * Decrypt with a key referenced in the key store.
   * The referenced key must be a jwk key.
   * @param algorithm used for signature
   * @param keyReference points to key in the key store
   * @param cipher to decrypt
   */
  public async decryptByKeyStore(algorithm: CryptoAlgorithm, keyReference: string, cipher: BufferSource): Promise<ArrayBuffer> {

    let jwk: PrivateKey = (await this.keyStore.get(keyReference, { publicKeyOnly: false })).getKey<PrivateKey>();
    const crypto: Subtle = CryptoHelpers.getSubtleCryptoForAlgorithm(this.cryptoFactory, algorithm, CryptoFactoryScope.Private);
    const keyImportAlgorithm: any = CryptoHelpers.getKeyImportAlgorithm(algorithm, jwk);

    const key = await crypto.importKey('jwk', jwk, keyImportAlgorithm, true, ['decrypt']);
    return crypto.decrypt(algorithm, key, <ArrayBuffer>cipher);
  }

  /**
   * Decrypt with JWK.
   * @param algorithm used for decryption
   * @param jwk Json web key to decrypt
   * @param cipher to decrypt
   */
  public async decryptByJwk(algorithm: CryptoAlgorithm, jwk: JsonWebKey, cipher: BufferSource): Promise<ArrayBuffer> {
    const crypto: Subtle = CryptoHelpers.getSubtleCryptoForAlgorithm(this.cryptoFactory, algorithm, CryptoFactoryScope.Private);
    const keyImportAlgorithm: any = CryptoHelpers.getKeyImportAlgorithm(algorithm, jwk);

    const key = await crypto.importKey('jwk', jwk, keyImportAlgorithm, true, ['decrypt']);
    return crypto.decrypt(algorithm, key, <ArrayBuffer>cipher);
  }

  /**
   * Encrypt with a jwk key referenced in the key store
   * @param algorithm used for encryption
   * @param jwk Json web key public key
   * @param data to encrypt
   */
  public async encryptByJwk(algorithm: CryptoAlgorithm, jwk: PublicKey | JsonWebKey, data: BufferSource): Promise<ArrayBuffer> {
    const keyImportAlgorithm: any = CryptoHelpers.getKeyImportAlgorithm(algorithm, jwk);

    const crypto: Subtle = CryptoHelpers.getSubtleCryptoForAlgorithm(this.cryptoFactory, algorithm, CryptoFactoryScope.Public);
    const key = await crypto.importKey('jwk', jwk, keyImportAlgorithm, true, ['encrypt']);
    return <PromiseLike<ArrayBuffer>>crypto.encrypt(algorithm, key, <ArrayBuffer>data);
  }

  /**
   * Export the key for the selected plugin
   * @param algorithm associated with the key
   * @param key The key material to export
   * @param scope for the key material
   */
  public async exportJwkKey(algorithm: Algorithm, key: CryptoKey, scope: CryptoFactoryScope): Promise<JsonWebKey> {
    const crypto: any = CryptoHelpers.getSubtleCryptoForAlgorithm(this.cryptoFactory, algorithm, scope);
    return crypto.exportKey('jwk', key);
  }
}
