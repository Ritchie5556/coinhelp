const crypto = require('crypto');

export class Role {
    constructor({ id, proofValue, credentialSubject }) {
        this.id = id;
        this.proofValue = proofValue;
        this.credentialSubject = credentialSubject;
        this.generateKeyPair(); // Generate key pair
        this.generateDIDDocument(); // Generate DID document
    }

    // Generate key pair
    generateKeyPair() {
        try {
            const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
                modulusLength: 2048, // Key length
            });

            // Export PEM format keys
            this.privateKeyPem = privateKey.export({
                type: 'pkcs8',
                format: 'pem'
            });

            this.publicKeyPem = publicKey.export({
                type: 'spki',
                format: 'pem'
            });

            console.log('Public and Private keys generated successfully.');
        } catch (error) {
            console.error('Error generating keys:', error);
        }
    }

    // Generate DID document
    generateDIDDocument() {
        this.didDocument = {
            "@context": "https://www.w3.org/ns/did/v1",
            id: this.id || 'did:example:123456',
            authentication: [
                {
                    id: `${this.id || 'did:example:123456'}#keys-1`,
                    type: "RsaVerificationKey2018",
                    controller: this.id || 'did:example:123456',
                    expirationDate: "", // Add expiration date if needed
                    publicKeyPem: this.publicKeyPem
                }
            ],
            service: [{
                id: `${this.id || 'did:example:123456'}#service1-1`,
                type: 'Service1',
                serviceEndpoint: 'https://example.com/service1'
            }],
            credentialSubject: this.credentialSubject || {
                url: '',
                id: '',
                number: '',
                name: '',
                category: '',
                time: '',
                institution: '',
            },
            proof: {
                type: "RsaSignature2018",
                created: new Date().toISOString(),
                expirationDate: "", // Add expiration date if needed
                proofPurpose: "assertionMethod",
                verificationMethod: `${this.id || 'did:example:123456'}#keys-1`,
                proofValue: this.proofValue || ""
            }
        };
    }

    // Sign data
    signData(data) {
        try {
            const sign = crypto.createSign('SHA256');
            sign.update(data);
            sign.end();
            return sign.sign(this.privateKeyPem, 'base64');
        } catch (error) {
            console.error('Error signing data:', error);
        }
    }

    // Verify signature with DID document ID and expiration dates
    verifySignature(data, signature) {
        try {
            // Validate DID document ID
            if (this.didDocument.id !== this.id) {
                console.error('DID Document ID mismatch.');
                return false;
            }

            // Check authentication expiration date
            const authExpirationDate = new Date(this.didDocument.authentication[0].expirationDate);
            if (this.didDocument.authentication[0].expirationDate && authExpirationDate <= new Date()) {
                console.error('Authentication credential expired.');
                return false;
            }

            // Check proof expiration date
            const proofExpirationDate = new Date(this.didDocument.proof.expirationDate);
            if (this.didDocument.proof.expirationDate && proofExpirationDate <= new Date()) {
                console.error('Proof expired.');
                return false;
            }

            // Verify the digital signature
            const verify = crypto.createVerify('SHA256');
            verify.update(data);
            verify.end();
            return verify.verify(this.publicKeyPem, signature, 'base64');
        } catch (error) {
            console.error('Error verifying signature:', error);
            return false;
        }
    }

    // Output DID Document and signature
    output() {
        try {
            console.log('DID Document:', JSON.stringify(this.didDocument, null, 2));

            // Use credentialSubject as the data to be signed
            const dataToSign = JSON.stringify(this.didDocument.credentialSubject);

            // Sign the data with the generated private key
            const signature = this.signData(dataToSign);
            console.log('Signature:', signature);

            // Verify the signature with the generated public key
            const isSignatureValid = this.verifySignature(dataToSign, signature);
            console.log('Is Signature Valid:', isSignatureValid ? 'Yes' : 'No');

            // Output generated public and private keys
            console.log('Public Key:', this.publicKeyPem);
            console.log('Private Key:', this.privateKeyPem);

            return { publicKey: this.publicKeyPem, privateKey: this.privateKeyPem, signature };
        } catch (error) {
            console.error('Error in output:', error);
        }
    }
}

module.exports = { Role };


// 实例化 PlatForm 并输出密钥
const PlatForm = new Role({
    name: "PlatForm",
    id: 'did:example:123456',
    proofValue: 'example-proof-value-1',
    credentialSubject: {
        url: 'https://example.com/subject1'
    }
});

const platFormKeys = PlatForm.output();


/*
//PlatForm实例
const PlatForm = new Role({
    name:"PlatForm",
    id:'did:example:123456', 
    proofValue:'example-proof-value-1', 
    credentialSubject:{
         url: 'https://example.com/subject1' 
    }
});
const platformSignature = PlatForm.output();

//Hospital实例
const Hospital = new Role({
    name:"Hospital",
    id:'did:example:914419007792270056', 
    proofValue:'example-proof-value-1', 
    credentialSubject:{
        id: '914419007792270056',
        number: '441900000037208',
        name: 'wangbaizhi',
        time: '2005-08-23',
        institution: 'RengKang Hospital',
    }
});
const hospitalSignature = Hospital.output();

//Doctor实例
const Doctor = new Role({
    name:"Doctor",
    id:'did:example:120320700000275', 
    proofValue:`${platformSignature},${hospitalSignature}`, 
    credentialSubject:{
        id: '120320700000275',
        name: 'xuwenping',
        category: 'oral cavity',
        institution: 'RengKang Hospital',
    }
});
const doctorSignature = Doctor.output();//将PlatForm和Hospital的签名加入proofValue

//Patient实例，将Doctor的签名加入proofValue
const Patient = new Role({
    name:"Patient",
    id:'did:example:123456', 
    proofValue: doctorSignature, 
    credentialSubject:{
         url: 'https://example.com/subject1' 
    }
});
Patient.output();
*/