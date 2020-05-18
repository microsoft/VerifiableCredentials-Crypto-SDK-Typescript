"use strict";
/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
Object.defineProperty(exports, "__esModule", { value: true });
exports.KeyUse = void 0;
/**
 * Enumeration to model key use.
 */
var KeyUse;
(function (KeyUse) {
    KeyUse["Encryption"] = "enc";
    KeyUse["Signature"] = "sig";
})(KeyUse = exports.KeyUse || (exports.KeyUse = {}));
/**
 * Factory class to create @enum KeyUse objects.
 */
class KeyUseFactory {
    /**
     * Create the key use according to the selected algorithm.
     * @param algorithm Web crypto compliant algorithm object
     */
    static createViaWebCrypto(algorithm) {
        switch (algorithm.name.toLowerCase()) {
            case 'hmac':
                return KeyUse.Signature;
            case 'ecdsa':
                return KeyUse.Signature;
            case 'eddsa':
                return KeyUse.Signature;
            case 'ecdh':
                return KeyUse.Encryption;
            case 'rsassa-pkcs1-v1_5':
                return KeyUse.Signature;
            case 'rsa-oaep':
            case 'rsa-oaep-256':
                return KeyUse.Encryption;
            default:
                throw new Error(`The algorithm '${algorithm.name}' is not supported`);
        }
    }
    /**
     * Create the key use according to the selected JWA algorithm.
     * @param alg JWA name
     */
    static createViaJwa(alg) {
        switch (alg.toLowerCase()) {
            case 'rs256':
            case 'rs384':
            case 'rs512':
            case 'es256k':
            case 'secp256k1':
            case 'ecdsa':
            case 'eddsa':
                return KeyUse.Signature;
            case 'rsa-oaep':
            case 'rsa-oaep-256':
            case 'a128gcm':
            case 'a256gcm':
            case 'a192gcm':
                return KeyUse.Encryption;
        }
        throw new Error(`Algorithm '${alg}' is not supported`);
    }
}
exports.default = KeyUseFactory;
//# sourceMappingURL=KeyUseFactory.js.map