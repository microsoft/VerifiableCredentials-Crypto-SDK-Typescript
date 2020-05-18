"use strict";
/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
Object.defineProperty(exports, "__esModule", { value: true });
exports.KeyOperation = void 0;
/**
 * JWK key operations
 */
var KeyOperation;
(function (KeyOperation) {
    KeyOperation["Sign"] = "sign";
    KeyOperation["Verify"] = "verify";
    KeyOperation["Encrypt"] = "encrypt";
    KeyOperation["Decrypt"] = "decrypt";
    KeyOperation["WrapKey"] = "wrapKey";
    KeyOperation["UnwrapKey"] = "unwrapKey";
    KeyOperation["DeriveKey"] = "deriveKey";
    KeyOperation["DeriveBits"] = "deriveBits";
})(KeyOperation = exports.KeyOperation || (exports.KeyOperation = {}));
/**
 * Represents a Public Key in JWK format.
 * @class
 * @abstract
 * @hideconstructor
 */
class JsonWebKey {
    /**
     * Create instance of @class JsonWebKey
     */
    constructor(key) {
        /**
         * Key ID
         */
        this.kid = '';
        this.kty = key.kty;
        this.kid = key.kid;
        this.use = key.use;
        this.key_ops = key.key_ops;
        this.alg = key.alg;
    }
}
exports.default = JsonWebKey;
//# sourceMappingURL=JsonWebKey.js.map