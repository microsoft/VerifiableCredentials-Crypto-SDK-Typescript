"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
/**
 * Represents a Key container in JWK format.
 * A key container will hold different versions of JWK keys.
 * Each key in the key container is the same type and usage
 */
class KeyContainer {
    /**
     * Create instance of @class KeyContainer
     */
    constructor(key) {
        this.keys = [key];
    }
    /**
     * Key type
     */
    get kty() {
        return this.keys[0].kty;
    }
    /**
     * Intended use
     */
    get use() {
        return this.keys[0].use;
    }
    /**
     * Algorithm intended for use with this key
     */
    get alg() {
        return this.keys[0].alg;
    }
    /**
     * Algorithm intended for use with this key
     */
    add(key) {
        // Check for valid key to add
        if (this.keys.length !== 0 && key.kty !== this.kty) {
            throw new Error(`Cannot add a key with kty '${key.kty}' to a key container with kty '${this.kty}'`);
        }
        if (this.keys.length !== 0 && key.use !== this.use) {
            throw new Error(`Cannot add a key with use '${key.use}' to a key container with use '${this.use}'`);
        }
        this.keys.push(key);
    }
    /**
     * Get the default key from the key container
     */
    getKey() {
        // return last keys as reference
        return this.keys[this.keys.length - 1];
    }
    /**
     * True if private key is a remote key
     */
    remotekey() {
        if (this.keys[0] && this.keys[0].kid) {
            return this.keys.length !== 0 && this.keys[0].kid.startsWith('https://');
        }
        return false;
    }
}
exports.default = KeyContainer;
//# sourceMappingURL=KeyContainer.js.map