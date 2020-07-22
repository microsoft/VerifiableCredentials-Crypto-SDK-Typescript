"use strict";
/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
Object.defineProperty(exports, "__esModule", { value: true });
const EcPublicKey_1 = require("./EcPublicKey");
const base64url_1 = require("base64url");
const clone = require('clone');
/**
 * Represents an Elliptic Curve private key
 * @class
 * @extends PrivateKey
 */
class EcPrivateKey extends EcPublicKey_1.default {
    /**
     * Create instance of @class EcPrivateKey
     */
    constructor(key) {
        super(key);
        /**
         * ECDSA w/ secp256k1 Curve
         */
        this.alg = 'ES256K';
        this.d = typeof key.d === 'string' ? key.d : base64url_1.default.encode(key.d);
    }
    /**
     * Gets the corresponding public key
     * @returns The corresponding {@link PublicKey}
     */
    getPublicKey() {
        const publicKey = clone(this);
        delete publicKey.d;
        return publicKey;
    }
}
exports.default = EcPrivateKey;
//# sourceMappingURL=EcPrivateKey.js.map