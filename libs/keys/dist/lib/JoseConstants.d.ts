/**
  * Class for JOSE constants
  */
export default class JoseConstants {
    /**
     * Define JOSE protocol name
     */
    static Jose: string;
    /**
     * Define JWE protocol name
     */
    static Jwe: string;
    /**
     * Define JWS protocol name
     */
    static Jws: string;
    /**
     * Define JOSE algorithm constants
     */
    static RsaOaep256: string;
    /**
     * Define JOSE algorithm constants
     */
    static RsaOaep: string;
    /**
    * Define JOSE algorithm constants
    */
    static Rs256: string;
    /**
     * Define JOSE algorithm constants
     */
    static Rs384: string;
    /**
     * Define JOSE algorithm constants
     */
    static Rs512: string;
    /**
     * Define JOSE algorithm constants
     */
    static EdDSA: string;
    /**
     * Define JOSE algorithm constants
     */
    static Es256K: string;
    /**
    * Define JOSE algorithm constants
    */
    static AesGcm128: string;
    /**
     * Define JOSE algorithm constants
     */
    static AesGcm192: string;
    /**
     * Define JOSE algorithm constants
     */
    static AesGcm256: string;
    /**
     * Define JOSE algorithm constants
     */
    static Hs256: string;
    /**
     * Define JOSE algorithm constants
     */
    static Sha256: string;
    /**
     * Define JOSE algorithm constants
     */
    static Hs512: string;
    /**
     * Define the default signing algorithm
     */
    static DefaultSigningAlgorithm: string;
    /**
     * Define the JOSE protocol elements
     */
    static Alg: string;
    /**
     * Define the JOSE protocol elements
     */
    static Kid: string;
    /**
     * Define the JOSE protocol elements
     */
    static Enc: string;
    /**
     * Define elements in the JWE Crypto Token
     */
    static tokenProtected: string;
    /**
     * Define elements in the JWE Crypto Token
     */
    static tokenUnprotected: string;
    /**
     * Define elements in the JWE Crypto Token
     */
    static tokenAad: string;
    /**
     * Define elements in the JWE Crypto Token
     */
    static tokenIv: string;
    /**
     * Define elements in the JWE Crypto Token
     */
    static tokenCiphertext: string;
    /**
     * Define elements in the JWS Crypto Token
     */
    static tokenTag: string;
    /**
     * Define elements in the JWE Crypto Token
     */
    static tokenRecipients: string;
    /**
     * Define elements in the JWS Crypto Token
     */
    static tokenPayload: string;
    /**
     * Define elements in the JWS Crypto Token
     */
    static tokenSignatures: string;
    /**
     * Define elements in the JWS Crypto Token
     */
    static tokenSignature: string;
    /**
     * Define elements in the JWS Crypto Token
     */
    static tokenFormat: string;
    /**
     * Define elements in the JOSE options
     */
    static optionProtectedHeader: string;
    /**
     * Define elements in the JOSE options
     */
    static optionHeader: string;
    /**
     * Define elements in the JOSE options
     */
    static optionKidPrefix: string;
    /**
     * Define elements in the JOSE options
     */
    static optionContentEncryptionAlgorithm: string;
    /**
     * Define JOSE serialization formats
     */
    static serializationJwsFlatJson: string;
    /**
     * Define JOSE serialization formats
     */
    static serializationJweFlatJson: string;
    /**
     * Define JOSE serialization formats
     */
    static serializationJwsGeneralJson: string;
    /**
     * Define JOSE serialization formats
     */
    static serializationJweGeneralJson: string;
}
