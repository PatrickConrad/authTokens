const crypto = require('crypto');
const path = require('path');

const {generateKeyPairSync} = crypto;
const fs = require('fs');
const type = (fileName) => fileName.toLowerCase().includes('private') ? 'privateKeys' : 'publicKeys'
const saveKey = (key, fileName, filePath = `../config/keys`) => {

  fs.writeFileSync(`${filePath}/${type(fileName)}/${fileName}.pem`, key, err => {
  if (err) {
      return console.log(err);
  }
  return console.log('File written')
  });
}

const readKey = (fileName, pathToFile = path.join(__dirname, `../config/keys`)) => {
  const key = fs.readFileSync(`${pathToFile}/${type(fileName)}/${fileName}.pem`, 'utf8', (err, data)=>{
      if(err){
          return console.log("Error: ", err.message);
      }
      return data
  })
  return key;
}

const createKeys = (password, keyName) => {
    const myKeys = generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
        },
        privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
        cipher: 'aes-256-cbc',
        passphrase: password ? password : 'top secret'
    }
  }, (err, publicKey, privateKey) => {
    if(!err){
      console.log(publicKey)
      console.log('\n')
      console.log('\n')
      console.log('\n')

      console.log(privateKey)
      return {publicKey, privateKey}
    }
    return console.log("Error: ", err.message);
  });
  
  saveKey(myKeys.privateKey, `${keyName}PrivateKey`);
  saveKey(myKeys.publicKey, `${keyName}PublicKey`);
}

module.exports = {
  createKeys,
  readKey, 
  saveKey
}