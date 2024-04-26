//Checking the crypto module
const crypto = require('crypto');
const {
  createECDH,
  createHash,
  getCurves,
} = require('node:crypto');

const AES_ALGORITHM = 'aes-256-cbc'; //Using AES encryption

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
	// The standard secure default length for RSA keys is 2048 bits
	modulusLength: 2048,
});
console.log(
	publicKey.export({
		type: "pkcs1",
		format: "pem",
	}),

	privateKey.export({
		type: "pkcs8",
		format: "pem",
	})
);

function testECDH() {
  console.log("ECDH curves", getCurves());
  const alice = createECDH('secp256k1');
  const bob = createECDH('secp256k1');
  
  // const privateKey = createHash('sha256').update('Secret Value', 'utf8').digest();
  // console.log(privateKey);
  // alice.setPrivateKey(privateKey);
  alice.generateKeys();
  console.log("alice");
  console.log("pub: "+alice.getPublicKey().toString('hex'));
  console.log("priv: "+alice.getPrivateKey().toString('hex'));
  
  // Bob uses a newly generated cryptographically strong pseudorandom key pair
  bob.generateKeys();
  console.log("bob");
  console.log("pub: "+bob.getPublicKey().toString('hex'));
  console.log("priv: "+bob.getPrivateKey().toString('hex'));
  
  const aliceSharedKey = alice.computeSecret(bob.getPublicKey(), null, 'hex');
  const bobSharedKey = bob.computeSecret(alice.getPublicKey(), null, 'hex');
  console.log("shared");
  console.log(aliceSharedKey);
  console.log(bobSharedKey);
  console.log(hash(aliceSharedKey));
  console.log(hash(bobSharedKey));
  console.log(hash(hash(aliceSharedKey)));
  console.log(hash(hash(hash(aliceSharedKey))));
  
  // aliceSecret and bobSecret should be the same shared secret value
  console.log(aliceSharedKey === bobSharedKey);
  return { alice, bob, shared: aliceSharedKey };
}

function hash(input) {
  return createHash('sha3-256').update(input, 'utf8').digest('hex');
}

//Encrypting text
function encryptAES(text, key, IV) {
   let iv = Buffer.from(IV, 'hex');
   let cipher = crypto.createCipheriv(AES_ALGORITHM, Buffer.from(key), iv);
   let encrypted = cipher.update(text);
   encrypted = Buffer.concat([encrypted, cipher.final()]);
   return { encryptedData: encrypted.toString('hex') };
}

// Decrypting text
function decryptAES(text, key, IV) {
   let iv = Buffer.from(IV, 'hex');
   let encryptedText = Buffer.from(text.encryptedData, 'hex');
   let decipher = crypto.createDecipheriv(AES_ALGORITHM, Buffer.from(key), iv);
   let decrypted = decipher.update(encryptedText);
   decrypted = Buffer.concat([decrypted, decipher.final()]);
   return decrypted.toString();
}

function encryptRSA(publicKey, data) {
  const result = crypto.publicEncrypt({
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha3-256",
    },
    // We convert the data string to a buffer using `Buffer.from`
    Buffer.from(data)
  );
  // The encrypted data is in the form of bytes, so we print it in base64 format
  // so that it's displayed in a more readable form
  console.log("encypted data: ", result.toString("base64"));
  return result;
}

function decryptRSA(privateKey, encryptedData) {
  const result = crypto.privateDecrypt({
      key: privateKey,
      // In order to decrypt the data, we need to specify the
      // same hashing function and padding scheme that we used to
      // encrypt the data in the previous step
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha3-256",
    },
    encryptedData);
  return result;
}

function signRSA(verifiableData) {
  const result = crypto.sign("sha3-256", Buffer.from(verifiableData), {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  });
  console.log("signature: "+result.toString("base64"));
  return result;
}

// To verify the data, we provide the same hashing algorithm and
// padding scheme we provided to generate the signature, along
// with the signature itself, the data that we want to
// verify against the signature, and the public key
function verifyRSA(verifiableData, signature) {
  const result = crypto.verify(
    "sha3-256",
    Buffer.from(verifiableData),
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    },
    signature);
  return result;
}

// Use ECDH to get a shared secret
const { alice, bob, shared } = testECDH();
console.log(shared?.length);
const key = shared?.length > 63 ? Buffer.from(shared.substring(0, 32)) : crypto.randomBytes(32);
const iv = shared?.length > 63 ? Buffer.from(shared.substring(32, 48)) : crypto.randomBytes(16);
// Encrypt/decrypt using AES
console.log("AES")
var hw = encryptAES("This is a great long string, that might be longer", key, iv)
console.log(hw)
console.log(decryptAES(hw, key, iv))
// Encrypt/decrypt using RSA
console.log("RSA");
const enc = encryptRSA(publicKey, "Test data");
console.log(decryptRSA(privateKey, enc).toString());
// Test sign and verify
const data = "this is a test";
const signature = signRSA(data);
const isVerified = verifyRSA(data, signature);
console.log(`isVerified: ${isVerified}`)