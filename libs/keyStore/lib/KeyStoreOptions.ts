/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Define the options for the key store
 */
export default class KeyStoreOptions {
  constructor(options?: any) {
    // set default values if not set by the constructor
    if (options) {
      this.publicKeyOnly = options.publicKeyOnly === undefined ? true : options.publicKeyOnly;
      this.extractable = options.extractable  === undefined ? true : options.extractable;
      this.latestVersion = options.latestVersion === undefined ? true : options.latestVersion;
    } else {
      // set defaults
      this.publicKeyOnly = true;
      this.extractable = true;
      this.latestVersion = true;    
    }
  }
  
  /**
   * True if only public keys are requested
   */
  public publicKeyOnly: boolean;

  /**
   * True if the key is extractable
   */
   public extractable?: boolean;

  /**
   * True if only the latest version of they is wanted
   */
   latestVersion?: boolean;
  }
