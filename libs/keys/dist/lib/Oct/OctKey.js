"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
const KeyTypeFactory_1 = require("../KeyTypeFactory");
const JsonWebKey_1 = require("../JsonWebKey");
/**
 * Represents an OCT key
 * @class
 * @extends JsonWebKey
 */
class OctKey extends JsonWebKey_1.default {
    /**
     * Create instance of @class EcPublicKey
     */
    constructor(key) {
        super({ kty: KeyTypeFactory_1.KeyType.Oct });
        /**
         * Set the Oct key type
         */
        this.kty = KeyTypeFactory_1.KeyType.Oct;
        this.k = key;
    }
}
exports.default = OctKey;
//# sourceMappingURL=OctKey.js.map