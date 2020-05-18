"use strict";
/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
Object.defineProperty(exports, "__esModule", { value: true });
const RsaPublicKey_1 = require("./RsaPublicKey");
const base64url_1 = require("base64url");
const clone = require('clone');
/**
 * Represents an Elliptic Curve private key
 * @class
 * @extends PrivateKey
 */
class RsaPrivateKey extends RsaPublicKey_1.default {
    /**
     * Create instance of @class RsaPrivateKey
     */
    constructor(key) {
        super(key);
        this.d = typeof key.d === 'string' ? key.d : base64url_1.default.encode(key.d);
        this.p = typeof key.p === 'string' ? key.p : base64url_1.default.encode(key.p);
        this.q = typeof key.q === 'string' ? key.q : base64url_1.default.encode(key.q);
        this.dp = typeof key.dp === 'string' ? key.dp : base64url_1.default.encode(key.dp);
        this.dq = typeof key.dq === 'string' ? key.dq : base64url_1.default.encode(key.dq);
        this.qi = typeof key.qi === 'string' ? key.qi : base64url_1.default.encode(key.qi);
    }
    /**
     * Gets the corresponding public key
     * @returns The corresponding {@link PublicKey}
     */
    getPublicKey() {
        const publicKey = clone(this);
        delete publicKey.d;
        delete publicKey.p;
        delete publicKey.q;
        delete publicKey.dp;
        delete publicKey.dq;
        delete publicKey.qi;
        return publicKey;
    }
}
exports.default = RsaPrivateKey;
//# sourceMappingURL=RsaPrivateKey.js.map