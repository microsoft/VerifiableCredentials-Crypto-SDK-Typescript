/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { CryptoKey } from 'webcrypto-core';

/**
 * Implementation of the CryptoKey for elliptic curve
 * based keys.
 */
export default class EllipticCurveSubtleKey extends CryptoKey {
  /**
   *
   * Gets the specification of the algorithm
   */
  public algorithm: KeyAlgorithm;

  /**
   * Key type
   */
  public type: KeyType;

  /**
   * Different usages supported by the provider
   */
  public usages: KeyUsage[];

  /**
   * True if key is exportable
   */
  public extractable: boolean;

  /**
   * The elliptic curve key
   */
  public key: any;

  /**
   * Create an instance of EllipticSubtleCurveKey
   * @param algorithm for the key
   * @param extractable True if key can be extracted
   * @param usages for the key
   * @param type of the key (private || public)
   * @param key to be used
   */
  constructor (algorithm: KeyAlgorithm, extractable: boolean, usages: KeyUsage[], type: KeyType, key: any) {
    super();
    this.algorithm = algorithm;
    this.type = type;
    this.usages = usages;
    this.extractable = extractable;
    this.key = key;
  }
}
