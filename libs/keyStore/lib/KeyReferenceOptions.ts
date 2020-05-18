/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Define the options for the key reference
 */
export default class KeyReferenceOptions {
  constructor(options: any) {
    // set default values if not set by the constructor
      this.keyReference = options.keyReference;
      this.extractable = options.extractable  === undefined ? true : options.extractable;
  }
  
  /**
   * True if only public keys are requested
   */
  public keyReference: string;

  /**
   * True if the key is extractable
   */
   public extractable?: boolean;
  }
