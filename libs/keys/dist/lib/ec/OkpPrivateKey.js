"use strict";
/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
Object.defineProperty(exports, "__esModule", { value: true });
const EcPublicKey_1 = require("./EcPublicKey");
const clone = require('clone');
/**
 * Represents an Elliptic Curve private key
 * @class
 * @extends PrivateKey
 */
class OkpPrivateKey extends EcPublicKey_1.default {
    /**
     * Create instance of @class EcPrivateKey
     */
    constructor(key) {
        super(key);
        /**
         * EdDSA w/ ed25519 Curve
         */
        this.alg = 'EdDSA';
        this.d = key.d;
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
exports.default = OkpPrivateKey;
//# sourceMappingURL=OkpPrivateKey.js.map