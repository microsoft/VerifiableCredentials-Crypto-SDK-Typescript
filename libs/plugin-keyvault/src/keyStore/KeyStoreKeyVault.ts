/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { ClientCertificateCredential, ClientSecretCredential, TokenCredential } from '@azure/identity';
import { KeyClient, JsonWebKey, CryptographyClient } from '@azure/keyvault-keys';
import { SecretClient } from '@azure/keyvault-secrets';
import { KeyStoreOptions, IKeyStore, KeyStoreListItem } from 'verifiablecredentials-crypto-sdk-typescript-keystore';
import { RsaPublicKey, EcPublicKey, KeyType, OctKey, KeyContainer, IKeyContainer, CryptographicKey, EcPrivateKey, RsaPrivateKey } from 'verifiablecredentials-crypto-sdk-typescript-keys';
import base64url from 'base64url';

/**
 * Key store class for accessing key vault
 */
export default class KeyStoreKeyVault implements IKeyStore {

  private keyClient: KeyClient;
  private secretClient: SecretClient;


  /**
   * Create a new instance of @class KeyStoreKeyVault
   * @param credential TokenCredential intance.
   * @param vaultUri of the key vault endpoint
   * @param defaultKeyStore Default IKeyStore implementation
   */
  constructor(
    private readonly credential: TokenCredential,
    vaultUri: string,
    private defaultKeyStore: IKeyStore
  ) {
    this.keyClient = new KeyClient(vaultUri, this.credential);
    this.secretClient = new SecretClient(vaultUri, this.credential);
  }


  /**
   * Returns the key container associated with the specified
   * key reference.
   * @param keyIdentifier for which to return the key.
     * @param [options] Options for retrieving.
   */
  public async get(keyReference: string, options: KeyStoreOptions = new KeyStoreOptions({ extractable: false })): Promise<any> {
    const client = this.getKeyStoreClient(options);
    const versionList: any[] = [];
    if (options.extractable) {
      // Get extractable secrets 
      // Check the cache first
      try {
        //const cached = await this.defaultKeyStore.get(keyReference, options);
        //return cached;
      } catch {
        // the key was not in the cache
        console.log(`${keyReference} not found in cache`)
      }

      const secretClient: SecretClient = <SecretClient>client;
      if (options.latestVersion) {
        const secret = await secretClient.getSecret(keyReference);
        (<any>secret).keyType = 'Oct';
        try {
          secret.value = JSON.parse(<string>secret.value);
          (<any>secret).keyType = (<any>secret.value).kty;
        } catch (e) {
          // no key container in secret
          console.log(`parsing of latest version of key from keyvault failed: ${keyReference}`);
        }

        versionList.push(secret);
      } else {
        for await (const keyProperties of secretClient.listPropertiesOfSecretVersions(keyReference)) {
          let secret = await secretClient.getSecret(keyReference, { version: keyProperties.version! });
          (<any>secret).keyType = 'Oct';
          try {
            secret.value = JSON.parse(<string>secret.value);
            (<any>secret).keyType = (<any>secret.value).kty;
          } catch {
            // no key container in secret
            console.log(`parsing of versions of key from keyvault failed: ${keyReference}`);
          }

          versionList.push(secret);
        }
      }
    } else {
      // Get non extractable keys returning public keys
      const keyClient: KeyClient = <KeyClient>client;
      if (options.latestVersion) {
        const key = await keyClient.getKey(keyReference);
        versionList.push(key);
      } else {
        for await (const keyProperties of keyClient.listPropertiesOfKeyVersions(keyReference)) {
          const key = await keyClient.getKey(keyReference, { version: keyProperties.version! });
          versionList.push(key);
        }
      }
    }

    let container: KeyContainer | undefined = undefined;
    let keyContainerItem: CryptographicKey | undefined;
    for (let inx = versionList.length - 1; inx >= 0; inx--) {
      const version = versionList[inx];
      const kty = (<string>version.keyType).toLocaleUpperCase();
      if (kty === 'OCT') {
        const value = version.value;
        keyContainerItem = new OctKey(value)
        if (container) {
          container.add(keyContainerItem);
        } else {
          container = new KeyContainer(keyContainerItem);
        }
      } else {
        if (options.extractable) {
          if (kty === 'EC') {
            keyContainerItem = options.publicKeyOnly ?
              new EcPublicKey(version.key ? version.key : version.value as any) : new EcPrivateKey(version.key ? version.key : version.value as any);
          } else {
            keyContainerItem = options.publicKeyOnly ?
              new RsaPublicKey(version.key ? version.key : version.value as any) : new RsaPrivateKey(version.key ? version.key : version.value as any);
          }
        } else {
          if (kty === 'EC') {
            keyContainerItem = new EcPublicKey(version.key ? version.key : version.value as any);
          } else {
            keyContainerItem = new RsaPublicKey(version.key ? version.key : version.value as any);
          }
        }

        if (container) {
          container.add(keyContainerItem);
        } else {
          container = new KeyContainer(keyContainerItem);
        }
      }

      // cache the private key
      if (keyContainerItem && options.extractable) {
        await this.defaultKeyStore.save(keyReference, keyContainerItem);
      }
    }

    if (!container) {
      throw new Error(`The secret with reference '${keyReference}' has not usable secrets`);
    }

    return container;
  }

  /**
   * Saves the specified secret to the key store using
   * the key reference.
   * @param keyReference Reference for the key being saved.
   * @param key being saved to the key store.
   * @param [options] Options for saving.
   */
  async save(keyReference: string, key: CryptographicKey | string, options: KeyStoreOptions = new KeyStoreOptions()): Promise<void> {
    const client = this.getKeyStoreClient(options);
    if (options.extractable) {
      const secretClient: SecretClient = <SecretClient>client;
      if (typeof key === 'object') {
        const serialKey = JSON.stringify(key);
        await secretClient.setSecret(keyReference, serialKey);
      } else {
        await secretClient.setSecret(keyReference, <string>key);
      }

    } else {
      const keyClient: KeyClient = <KeyClient>client;
      const kvKey: CryptoKeyPair = KeyStoreKeyVault.toKeyVaultKey(<IKeyContainer>key);
      
      await keyClient.importKey(keyReference, kvKey);
    }
  }

  /**
   * Lists all key references with their corresponding key ids
   */
  async list(options: KeyStoreOptions = new KeyStoreOptions()): Promise<{ [name: string]: KeyStoreListItem }> {
    const client = this.getKeyStoreClient(options);
    const list: { [name: string]: KeyStoreListItem } = {};
    if (options.extractable) {
      const secretClient: SecretClient = <SecretClient>client;
      for await (const secretProperties of secretClient.listPropertiesOfSecrets()) {
        list[secretProperties.name] = <KeyStoreListItem>{
          kids: [secretProperties.id],
          kty: KeyType.Oct
        };

        if (!options.latestVersion) {
          list[secretProperties.name].kids = [];
          for await (const versionProperties of secretClient.listPropertiesOfSecretVersions(secretProperties.name)) {
            list[secretProperties.name].kids.push(<string>versionProperties.id);
          }
        }
      }
    } else {
      const keyClient: KeyClient = <KeyClient>client;
      for await (const keyProperties of keyClient.listPropertiesOfKeys()) {
        const key = await keyClient.getKey(keyProperties.name);
        list[keyProperties.name] = <KeyStoreListItem>{
          kids: [keyProperties.id],
          kty: key.keyType
        };

        if (!options.latestVersion) {
          list[keyProperties.name].kids = [];
          for await (const versionProperties of keyClient.listPropertiesOfKeyVersions(keyProperties.name)) {
            list[keyProperties.name].kids.push(<string>versionProperties.id);
          }
        }
      }
    }
    return list;
  }

  /**
   * Convert key container into a key vault compatible key
   * @param container to convert
   */
  public static toKeyVaultKey(container: IKeyContainer): CryptoKeyPair {
    const key: any = (<IKeyContainer>container).getKey<CryptographicKey>();
    if (key.kty === KeyType.EC || key.kty === 'EC') {
      key.kty = 'EC';
      key.x = new Uint8Array(base64url.toBuffer(key.x).buffer);
      key.y = new Uint8Array(base64url.toBuffer(key.y).buffer);
      if (key.d) {
        key.d = new Uint8Array(base64url.toBuffer(key.d).buffer);
      }
    } else if (key.kty === KeyType.RSA || key.kty === 'RSA') {
      key.kty = 'RSA'
      key.e = new Uint8Array(base64url.toBuffer(key.e));
      key.n = new Uint8Array(base64url.toBuffer(key.n));
      if (key.d) {
        key.d = new Uint8Array(base64url.toBuffer(key.d));
        key.p = new Uint8Array(base64url.toBuffer(key.p));
        key.q = new Uint8Array(base64url.toBuffer(key.q));
        key.dp = new Uint8Array(base64url.toBuffer(key.dp));
        key.dq = new Uint8Array(base64url.toBuffer(key.dq));
        key.qi = new Uint8Array(base64url.toBuffer(key.qi));
      }
    }

    return key;
  }

  /**
   * Get the client to access the key vault store
   */
  public getKeyStoreClient(options: KeyStoreOptions): KeyClient | SecretClient {
    if (options.extractable) {
      return this.secretClient;
    } else {
      return this.keyClient;
    }
  }

  /**
   * Get the client for crypto operations by the specified key
   * @param kid referencing the key for the crypto operations
   */
  public getCryptoClient(kid: string) {
    return new CryptographyClient(kid, this.credential);
  }
}
