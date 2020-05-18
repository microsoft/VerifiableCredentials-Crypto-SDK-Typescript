"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
/**
  * Class for JOSE constants
  */
let JoseConstants = /** @class */ (() => {
    class JoseConstants {
    }
    /**
     * Define JOSE protocol name
     */
    JoseConstants.Jose = 'JOSE';
    /**
     * Define JWE protocol name
     */
    JoseConstants.Jwe = 'JWE';
    /**
     * Define JWS protocol name
     */
    JoseConstants.Jws = 'JWS';
    /**
     * Define JOSE algorithm constants
     */
    JoseConstants.RsaOaep256 = 'RSA-OAEP-256';
    /**
     * Define JOSE algorithm constants
     */
    JoseConstants.RsaOaep = 'RSA-OAEP';
    /**
    * Define JOSE algorithm constants
    */
    JoseConstants.Rs256 = 'RS256';
    /**
     * Define JOSE algorithm constants
     */
    JoseConstants.Rs384 = 'RS384';
    /**
     * Define JOSE algorithm constants
     */
    JoseConstants.Rs512 = 'RS512';
    /**
     * Define JOSE algorithm constants
     */
    JoseConstants.EdDSA = 'EDDSA';
    /**
     * Define JOSE algorithm constants
     */
    JoseConstants.Es256K = 'ES256K';
    /**
    * Define JOSE algorithm constants
    */
    JoseConstants.AesGcm128 = 'A128GCM';
    /**
     * Define JOSE algorithm constants
     */
    JoseConstants.AesGcm192 = 'A192GCM';
    /**
     * Define JOSE algorithm constants
     */
    JoseConstants.AesGcm256 = 'A256GCM';
    /**
     * Define JOSE algorithm constants
     */
    JoseConstants.Hs256 = 'HS256';
    /**
     * Define JOSE algorithm constants
     */
    JoseConstants.Sha256 = 'SHA-256';
    /**
     * Define JOSE algorithm constants
     */
    JoseConstants.Hs512 = 'HS512';
    /**
     * Define the default signing algorithm
     */
    JoseConstants.DefaultSigningAlgorithm = JoseConstants.Es256K;
    /**
     * Define the JOSE protocol elements
     */
    JoseConstants.Alg = 'alg';
    /**
     * Define the JOSE protocol elements
     */
    JoseConstants.Kid = 'kid';
    /**
     * Define the JOSE protocol elements
     */
    JoseConstants.Enc = 'enc';
    /**
     * Define elements in the JWE Crypto Token
     */
    JoseConstants.tokenProtected = 'protected';
    /**
     * Define elements in the JWE Crypto Token
     */
    JoseConstants.tokenUnprotected = 'unprotected';
    /**
     * Define elements in the JWE Crypto Token
     */
    JoseConstants.tokenAad = 'aad';
    /**
     * Define elements in the JWE Crypto Token
     */
    JoseConstants.tokenIv = 'iv';
    /**
     * Define elements in the JWE Crypto Token
     */
    JoseConstants.tokenCiphertext = 'ciphertext';
    /**
     * Define elements in the JWS Crypto Token
     */
    JoseConstants.tokenTag = 'tag';
    /**
     * Define elements in the JWE Crypto Token
     */
    JoseConstants.tokenRecipients = 'recipients';
    /**
     * Define elements in the JWS Crypto Token
     */
    JoseConstants.tokenPayload = 'payload';
    /**
     * Define elements in the JWS Crypto Token
     */
    JoseConstants.tokenSignatures = 'signatures';
    /**
     * Define elements in the JWS Crypto Token
     */
    JoseConstants.tokenSignature = 'signature';
    /**
     * Define elements in the JWS Crypto Token
     */
    JoseConstants.tokenFormat = 'format';
    /**
     * Define elements in the JOSE options
     */
    JoseConstants.optionProtectedHeader = 'ProtectedHeader';
    /**
     * Define elements in the JOSE options
     */
    JoseConstants.optionHeader = 'Header';
    /**
     * Define elements in the JOSE options
     */
    JoseConstants.optionKidPrefix = 'KidPrefix';
    /**
     * Define elements in the JOSE options
     */
    JoseConstants.optionContentEncryptionAlgorithm = 'ContentEncryptionAlgorithm';
    /**
     * Define JOSE serialization formats
     */
    JoseConstants.serializationJwsFlatJson = 'JwsFlatJson';
    /**
     * Define JOSE serialization formats
     */
    JoseConstants.serializationJweFlatJson = 'JweFlatJson';
    /**
     * Define JOSE serialization formats
     */
    JoseConstants.serializationJwsGeneralJson = 'JwsGeneralJson';
    /**
     * Define JOSE serialization formats
     */
    JoseConstants.serializationJweGeneralJson = 'JweGeneralJson';
    return JoseConstants;
})();
exports.default = JoseConstants;
//# sourceMappingURL=JoseConstants.js.map