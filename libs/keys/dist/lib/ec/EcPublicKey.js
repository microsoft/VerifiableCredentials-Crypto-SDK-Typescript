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
 * Represents an Elliptic Curve public key
 * @class
 * @extends PublicKey
 */
class EcPublicKey extends JsonWebKey_1.default {
    /**
     * Create instance of @class EcPublicKey
     */
    constructor(key) {
        super(key);
        this.crv = key.crv;
        this.x = typeof key.x === 'string' ? key.x : base64url_1.default.encode(key.x);
        if (key.y) {
            // No y for OPK
            this.y = typeof key.y === 'string' ? key.y : base64url_1.default.encode(key.y);
            this.kty = KeyTypeFactory_1.KeyType.EC;
        }
        else {
            this.y = undefined;
            this.kty = KeyTypeFactory_1.KeyType.OKP;
        }
    }
}
exports.default = EcPublicKey;
//# sourceMappingURL=EcPublicKey.js.map