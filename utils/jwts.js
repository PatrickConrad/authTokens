const crypto = require('crypto');
const {createKeys, readKey} = require('./keys');

const convert = (jsData, fromBase = false) => {
    if(!fromBase) {
        const conversion = Buffer.from(JSON.stringify(jsData)).toString('base64');
        return conversion;
    }
    else{
        const conversion = Buffer.from(jsData, 'base64').toString('ascii');
        return conversion;
    }
}

const signToken = (key, data, options= {alg: 'RSA-SHA256'}) => {
    const dataString = Buffer.from(JSON.stringify(data));
    const sig = crypto.sign(options.alg, dataString, {key, passphrase: '12345'}).toString('base64');
    const token = `${convert(options)}.${convert(data)}.${sig}`;
    return token;
}

const verifyToken = (token, key) => {
    const segments = (tkn) => {
        const segment = tkn.split('.');
        return {
            header: JSON.parse(convert(segment[0], true)),
            payload: convert(segment[1], true),
            signature: Buffer.from(segment[2], 'base64')
        }
    }
    const {header, payload, signature} = segments(token);
    
    const verify = crypto.verify(header.algorithm, Buffer.from(payload), key, signature);
    return {isVerified: verify, expired: parseInt(header.crt)+parseInt(header.exp)<Date.now()?true:false, payload: JSON.parse(payload), header}
}

//-----------Testing------------------

const testData = {username: 'Pat', id: '123hi', roles: ['user', 'admin']}
const testOptions = {exp: '5000', alg: 'RSA-SHA256', iss: 'mytest', sub: 'user', aud: 'mytest.com', crt: Date.now().toString()}
// createKeys('12345', 'refreshToken')
const privateKey = readKey('refreshTokenPrivateKey')
const publicKey = readKey('refreshTokenPublicKey')
// 
const token = signToken(privateKey, testData, testOptions)
console.log("token: ", token)
const info = verifyToken(token, publicKey)
console.log('verified token info: ', info)

module.exports = {
    verifyToken,
    signToken
}