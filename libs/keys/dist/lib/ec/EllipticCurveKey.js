"use strict";
/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
Object.defineProperty(exports, "__esModule", { value: true });
const webcrypto_core_1 = require("webcrypto-core");
/**
 * Implementation of the CryptoKey for elliptic curve
 * based keys.
  */
class EllipticCurveKey extends webcrypto_core_1.CryptoKey {
    /**
     * Create an instance of EcCryptoKey
     * @param algorithm for the key
     * @param extractable True if key can be extracted
     * @param usages for the key
     * @param type of the key (private || public)
     * @param key to be used
     */
    constructor(algorithm, extractable, usages, type, key) {
        super();
        this.algorithm = algorithm;
        this.type = type;
        this.usages = usages;
        this.extractable = extractable;
        this.key = key;
    }
}
exports.default = EllipticCurveKey;
//# sourceMappingURL=EllipticCurveKey.js.map