describe('signing with secp256k1', async () => {

    // Create default subtle API
    const subtle = SubtleCryptoFactory.create('SubtleCryptoNode');

    // Generate a secp256k1 key pair
    const key = await subtle.generateKey(
        {
            name: "ECDSA",
            namedCurve: "secp256k1"
        },        
        true, 
        ["sign", "verify"]);
    
    // Export the key into JWK format. Only possible if key was generated with extractable = true.
    const jwk = await subtle.exportKey(
        'jwk',
        key.privateKey);

    // Create ECDSA signatrue
    cont signature = await subtle.sign(
        {
            name: "ECDSA",
            hash: {name: "SHA-256"}
        },        
        key.privateKey, 
        Buffer.from('Payload to sign')); 

    // Verify the signature
    const result = await subtle.verify(
        {                
            name: "ECDSA",
            hash: {name: "SHA-256"}
        },
        key.publicKey,             
        signature, 
        Buffer.from('Payload to sign')); 
    expect(result).toBeTruthy();
    
})