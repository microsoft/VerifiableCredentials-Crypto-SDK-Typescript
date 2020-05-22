# The Verifiable Credentials Crypto SDK
This SDK is a set of crypto tools orginally designed for the use within the DID community. See  [Decentralized Identity Foundation](https://identity.foundation/).

## Goal - Provide crypto primitives used within DID
DID has defined a set of protocols supported by cryptographic primitives. This SDK will implement most of these cryptographic primitives.
This includes algorithms such as: 
* ECDSA (secp256k1)
* RSA signing (RSASSA-PKCS1-v1_5)
* RSA encryption (RSA-OAEP)
* AES GCM
* Digests (SHA-256, SHA-384, SHA-512)
* HMAC (HS256, HS384, HS512)
* EdDSA (ed25519) - still experimental
* And several more not actively used within DIF

## Goal - Provide a standardized API 
The primitives API is based on the [W3C Web Crypto API](https://www.w3.org/TR/WebCryptoAPI/). 

The SDK uses several layers or crypto implementations:

* Most the algorithms are the ones implemented in Nodejs crypro. No need to rewrite them.
* For Elliptic curve ed25519 the npm package elliptic is used.
* The subtle crypto API is provided by the excellent work of [@peculiar/webcrypto](https://www.npmjs.com/package/@peculiar/webcrypto).

## Goal - Plugeable Crypto layers
The goal of plugeable crypto is to make application completely agnostic to the used algorithm, even hardware enviroments. 
The algorithms to use should be in some configuration and as such a standardized API can be used for any crypto calls.
A change in algorithms should only happen in configuration and does not impact the application itself.

As such we can configure an application to do all private key operations on another service (hardware security module) such as [Key Vault](https://docs.microsoft.com/en-us/azure/key-vault/general/). This implies that keys can be generated on Key Vault and all private key operations will happen on Key Vault. A such there is no need for the private key to ever leave Key Vault.

A test enviroment might not need the same level of security and could generate and use keys on nodejs.


# Concepts

## KeyStore
KeyStore is an abstraction where cryptographic keys are going to be stored. This SDK provides to key stores:

* KeyStoreInMemory Simple cache in memory for keys
* KeyStoreKeyVault Store the keys on Key Vault

You can use the KeyStoreFactory.create('KeyStoreInMemory') to create the KeyStore to use.

## SubtleCrypto
SubtleCrypto is the standardized API defined by W3C. 

    const key = await subtle.generateKey(
        {
            name: "HMAC",
            hash: {name: "SHA-256"}, 
            length: 256
        },
        true, 
        ["sign", "verify"])

This is an example how to generate an HMAC key. Next we can export this key into a [Json Web Key](https://tools.ietf.org/html/rfc7517)


    const jwk = await subtle.exportKey(
        "jwk",
        key)

We could also sign with this key.

    cont signature = await subtle.sign(
        {
            name: "HMAC",
        },
        key, 
        data) //ArrayBuffer of data you want to sign

Have look to a look at the subtle API examples on github [diafygi/webcrypto-examples](https://github.com/diafygi/webcrypto-examples/).

Use the SubtleCryptoFactory.create('SubtleCryptoNode') factory method to create the default SubtleCrypto API.


## CryptoFactory

The CryptoFactory defines which KeyStore to use and which plugins for which algorithms. You can make your own CryptoFactory and add your own plugins to it.
Have look to CrytoFactoryNode which is the default crypto factory. It maps the EDDSA algorithm to a special provider because EDDSA is not implemented in nodejs crypto.

    export default class CryptoFactoryNode extends CryptoFactory {
       /**
        * Constructs a new CryptoFactoryNode
        * @param keyStore used to store private keys
        * @param crypto Default subtle crypto used for e.g. hashing.
        */
        constructor (keyStore: IKeyStore, crypto: any) {
            super(keyStore, crypto);
            const subtleCrypto: any = new SubtleCryptoElliptic(crypto);
            this.addMessageSigner('EdDSA', {subtleCrypto, scope: CryptoFactoryScope.All});
            this.addMessageSigner('EDDSA', {subtleCrypto, scope: CryptoFactoryScope.All});
            this.addMessageSigner('ed25519', {subtleCrypto, scope: CryptoFactoryScope.All});
        }
    }

Use the CryptoFactoryManager.create('CryptoFactoryNode', new SubtleCrypto()) factory method to create the default SubtleCrypto API.

# Getting started

## Install

npm install -g @microsoft/rush

rush update

## Build

rush build

## test

The SDK is an assembly of smaller NPM packages. You can go into the directory of these packages and do npm run test to test the package.


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
