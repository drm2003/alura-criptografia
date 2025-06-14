import { generateKeyPairSync } from 'crypto';

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,

    publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
    },
});

// console.log(publicKey);
// console.log(privateKey);


import { publicEncrypt, privateDecrypt } from 'crypto';

const dadosCriptografados = publicEncrypt(
    publicKey,
    Buffer.from("Mensagem super secreta")
);

console.log(dadosCriptografados.toString('hex'));


const dadosDecriptografados = privateDecrypt(
    privateKey,
    dadosCriptografados
);

console.log(`Dados decifrados: ${dadosDecriptografados.toString('utf-8')}`);

