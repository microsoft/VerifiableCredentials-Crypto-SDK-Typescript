"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
const KeyTypeFactory_1 = require("../KeyTypeFactory");
const JsonWebKey_1 = require("../JsonWebKey");
const base64url_1 = require("base64url");
/**
 * Represents an RSA public key
 * @class
 * @extends PublicKey
 */
class RsaPublicKey extends JsonWebKey_1.default {
    /**
     * Create instance of @class RsaPublicKey
     */
    constructor(key) {
        super(key);
        /**
         * Set the EC key type
         */
        this.kty = KeyTypeFactory_1.KeyType.RSA;
        /**
         * Set the default algorithm
         */
        this.alg = 'RS256';
        this.alg = key.alg;
        this.key_ops = key.key_ops;
        this.kid = key.kid;
        this.use = key.use;
        this.e = typeof key.e === 'string' ? key.e : base64url_1.default.encode(key.e);
        this.n = typeof key.n === 'string' ? key.n : base64url_1.default.encode(key.n);
    }
}
exports.default = RsaPublicKey;
//# sourceMappingURL=RsaPublicKey.js.map