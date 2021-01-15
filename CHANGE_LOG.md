# version 1.1.12-preview.1
## Keyvault exportKey did not add the kid in the jwk.
**Type of change:** engineering    
**Customer impact:** low

## Round one to come to 100% line coverage.
**Type of change:** engineering    
**Customer impact:** low

# version 1.1.12-preview.0
## Remove all console.log calls from the SDK
**Type of change:** engineering    
**Customer impact:** low

# version 1.1.11
## Support for json-ld proofs
**Type of change:** new feature    
**Customer impact:** low

Creation of json-ld proofs is supported.
By default Jose signatures will be in the JWT format.

Add useJsonLdProofsProtocol to the JoseBuilder to support json-ld proofs:

          let jsonLdProofBuilder = new JoseBuilder(crypto)
            .useJsonLdProofsProtocol('JcsEd25519Signature2020')

For the moment only the JcsEd25519Signature2020 cipher suite is supported. See https://identity.foundation/JcsEd25519Signature2020/

## Improved performance of the Key Vault plugin
**Type of change:** engineering    
**Customer impact:** low

Additional caching improves the performance of the Key Vault operations.

## Update sidetree package to remove vulnerability reporting
**Type of change:** security    
**Customer impact:** low

The sidetree package was reporting high risk vulnerabilities. Updated to the latest version.




