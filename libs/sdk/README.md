

# Repo

[https://github\.com/microsoft/VerifiableCredentials\-Crypto\-SDK\-Typescript](https://github.com/microsoft/VerifiableCredentials-Crypto-SDK-Typescript)

 

# Goals

## Goal \- Provide crypto primitives used within DID

DID has defined a set of protocols supported by cryptographic primitives\. This SDK will implement most of these cryptographic primitives\. This includes algorithms such as:

- ECDSA \(secp256k1)
- RSA signing \(RSASSA\-PKCS1\-v1\_5)
- RSA encryption \(RSA\-OAEP)
- AES GCM
- Digests \(SHA\-256, SHA\-384, SHA\-512)
- HMAC \(HS256, HS384, HS512)
- EdDSA \(ed25519) \- still experimental

## Goal \- Provide a standardized API

The crypto API is based on the [W3C Web Crypto API](https://www.w3.org/TR/WebCryptoAPI/)\. This is typically referred to as Web Crypto, SubtleCrypto or subtle\.

The SDK uses several layers or crypto implementations:

Most the algorithms are implemented in Nodejs crypto\. No need to rewrite them\.

For Elliptic curve ed25519 the npm package elliptic is used\.

The subtle crypto API is provided by the excellent work of [@peculiar/webcrypto](https://www.npmjs.com/package/@peculiar/webcrypto)\.

See [diafygi/webcrypto\-examples](https://github.com/diafygi/webcrypto-examples/) for an extensive list of examples on how to use subtle\.

## Goal \- Support for payload protection

The crypto SDK provides support for protecting payloads\. The protocol support is provided in a layer above subtle crypto and uses the pluggable crypto concept \(see further)\.

__Supported protocols:__

- [JSON Web Signature \(JWS) \- RFC 7515](https://tools.ietf.org/html/rfc7515)\.
- [JSON Web Encryption \(JWE) \- RFC 7516](https://tools.ietf.org/html/rfc7516)\.
- [JSON Web Key \(JWK) \- RFC 7517](https://tools.ietf.org/html/rfc7517)\.
- [JSON Web Token \(JWT) \- RFC 7519\. Only signed payloads](https://tools.ietf.org/html/rfc7519)\.

## Goal \- Pluggable Crypto layers

The goal of pluggable crypto is to make applications agnostic to the used algorithms and hardware environments\. The applications specify the used algorithms in configuration and as such a standardized API can be used for any crypto calls\.  So, changing algorithms or hardware environments will not impact the applications themselves\.

### Key Vault

We can configure an application to do all private key operations on another service \(hardware security module) such as [Key Vault](https://docs.microsoft.com/en-us/azure/key-vault/general/)\. This implies that keys can be generated on Key Vault and all private key operations will happen on Key Vault\. A such there is no need for the private key to ever leave the secure Key Vault environment\.

A test environment might not need the same level of security and could generate and use keys on nodejs, while the same application in production will use Key Vault\. This behavior can be achieve by just changing the application’s configuration\.

# Concepts

## KeyStore

KeyStore is an abstraction of where cryptographic keys are stored\. This SDK provides two key stores:

- KeyStoreInMemory: Simple cache in memory for keys
- KeyStoreKeyVault: Store the keys on Key Vault

KeyStores can be created by honoring the IKeyStore interface, as such application builder can write their own plugins with new key stores\.

You can use the KeyStoreFactory\.create\('KeyStoreInMemory') to create the KeyStore, KeyStoreInMemory in this case\.

## SubtleCrypto

SubtleCrypto is the standardized API defined by W3C and is the basis of the primitives API\.

    const subtle = SubtleCryptoFactory\.create\('SubtleCryptoNode');  
    const key = await subtle\.generateKey\(  
        {  
            name: "ECDSA",  
            namedCurve: "secp256k1"  
        },          
        true,   
        ["sign", "verify"]);

This is an example how to generate a secp256k1 key, commonly used in the DID community\. Next we can export this key into a [Json Web Key](https://tools.ietf.org/html/rfc7517)

    const jwk = await subtle\.exportKey\(  
        "jwk",  
        key\.privateKey);

We can also sign with this generated private key\.

    cont signature = await subtle\.sign\(  
        {  
            name: "ECDSA",  
            hash: {name: "SHA\-256"}  
        },          
        key\.privateKey,   
        Buffer\.from\('Payload to sign')); 

And finally verify the signature

    const result = await subtle\.verify\(  
        {  
            name: "ECDSA",  
            hash: {name: "SHA\-256"}  
        },  
        key\.publicKey,   
        signature,   
        Buffer\.from\('Payload to sign')); 

Checkout the /samples folder for samples\. Have a look at the subtle API examples on github [diafygi](https://github.com/diafygi/webcrypto-examples/)[/](https://github.com/diafygi/webcrypto-examples/)[webcrypto](https://github.com/diafygi/webcrypto-examples/)[\-examples](https://github.com/diafygi/webcrypto-examples/)\.

Use the SubtleCryptoFactory\.create\('SubtleCryptoNode') factory method to create the default SubtleCrypto API\.

## CryptoFactory

The CryptoFactory defines which KeyStore to use and which plugins for which algorithms\. You can make your own CryptoFactory and add your own plugins to it\. Have a look to CrytoFactoryNode which is the default crypto factory\. It maps the EDDSA algorithm to a special provider because EDDSA is not implemented in nodejs crypto\.

    export default class CryptoFactoryNode extends CryptoFactory {  
    /**  
        * Constructs a new CryptoFactoryNode  
        * @param keyStore used to store private keys  
        * @param crypto Default subtle crypto used for e\.g\. hashing\.  
        */  
        constructor \(keyStore: IKeyStore, crypto: any) {  
            super\(keyStore, crypto);  
            const subtleCrypto: any = new SubtleCryptoElliptic\(crypto);  
            this\.addMessageSigner\('EdDSA', {subtleCrypto, scope: CryptoFactoryScope\.All});  
            this\.addMessageSigner\('EDDSA', {subtleCrypto, scope: CryptoFactoryScope\.All});  
            this\.addMessageSigner\('ed25519', {subtleCrypto, scope: CryptoFactoryScope\.All});  
        }  
    }

Use the CryptoFactoryManager\.create\('CryptoFactoryNode', new SubtleCrypto\()) factory method to create the default SubtleCrypto API\.

## Pairwise keys

Pairwise keys are a special set of key generation algorithms which allows you to generate a deterministic key that can be used between two parties\. This means that these keys can be generated on the fly when needed and they do not need to be stored\.

Pairwise keys are supported for ECDSA and RSA signatures\.

# Getting started

## Install

To add the sdk to your package\.json:

npm i verifiablecredentials\-crypto\-sdk\-typescript

## Cloning

If you want to clone the SDK, you need to use [rush](https://rushjs.io/)\. The crypto SDK is assembled by several smaller packages\. Rush is transparent to applications using the SDK\. The only install verifiablecredentials\-crypto\-sdk\-typescript\.

### Install rush

npm install \-g @microsoft/rush

### Update all packages

rush update or rush update \-\-full for a refresh

### Build

rush build or rush rebuild to force a full build

### Test

The SDK is an assembly of smaller NPM packages\. You can go into the directory of each packages and do npm run test to test the package\.

 
# 
# 

# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
