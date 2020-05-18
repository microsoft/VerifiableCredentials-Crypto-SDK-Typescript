import { KeyUse } from './KeyUseFactory';
import { KeyType } from './KeyTypeFactory';
import IKeyContainer, { CryptographicKey } from './IKeyContainer';
/**
 * Represents a Key container in JWK format.
 * A key container will hold different versions of JWK keys.
 * Each key in the key container is the same type and usage
 */
export default class KeyContainer implements IKeyContainer {
    /**
     * Create instance of @class KeyContainer
     */
    constructor(key: CryptographicKey);
    /**
     * Return all keys in the container
     */
    keys: CryptographicKey[];
    /**
     * Key type
     */
    get kty(): KeyType;
    /**
     * Intended use
     */
    get use(): KeyUse | undefined;
    /**
     * Algorithm intended for use with this key
     */
    get alg(): string | undefined;
    /**
     * Algorithm intended for use with this key
     */
    add(key: CryptographicKey): void;
    /**
     * Get the default key from the key container
     */
    getKey<T = CryptographicKey>(): T;
    /**
     * True if private key is a remote key
     */
    remotekey(): boolean;
}
