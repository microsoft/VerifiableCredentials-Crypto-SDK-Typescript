"use strict";
/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
Object.defineProperty(exports, "__esModule", { value: true });
exports.KeyOperation = void 0;
const base64url_1 = require("base64url");
const JsonWebKey_1 = require("./JsonWebKey");
const jose = require('node-jose');
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
class PublicKey extends JsonWebKey_1.default {
    /**
     * Obtains the thumbprint for the jwk parameter
     * @param jwk JSON object representation of a JWK
     */
    static async getThumbprint(publicKey) {
        const key = await jose.JWK.asKey(publicKey);
        const thumbprint = await key.thumbprint('SHA-256');
        return base64url_1.default.encode(thumbprint);
    }
}
exports.default = PublicKey;
//# sourceMappingURL=PublicKey.js.map