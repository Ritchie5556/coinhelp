import fs from 'fs'; // 需要使用浏览器兼容的库
import crypto from 'crypto'; // 需要使用浏览器兼容的库
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { Role } from './2.js';
 // 从2.js文件导入Role类

// 创建 S3 客户端
const s3Client = new S3Client({
    endpoint: 'https://gateway.storjshare.io',
    region: 'us1',
    credentials: {
        accessKeyId: "jvvigoqrpmfvi3oqe6glaesyg6ya",
        secretAccessKey: "j2kg7eacv2k2vl7fjp7wkm4qpsge2veqqhrcn6xt3ogsx7nbfz7mg"
    },
    forcePathStyle: true
});

// 创建 PlatForm 实例并获取公钥和私钥
const PlatForm = new Role({
    name: "PlatForm",
    id: 'did:example:123456',
    proofValue: 'example-proof-value-1',
    credentialSubject: {
        url: 'https://example.com/subject1'
    }
});
const platFormPublicKey = PlatForm.publicKeyPem; // 获取公钥
const platFormPrivateKey = PlatForm.privateKeyPem; // 获取私钥

// 对文件内容进行加密
function encryptFile(filePath, publicKey) {
    const fileBuffer = fs.readFileSync(filePath);
    const encrypted = crypto.publicEncrypt(publicKey, fileBuffer);
    console.log('Encrypted content:', encrypted.toString('base64'));
    return encrypted;
}

// 解密文件内容
function decryptFile(encryptedContent, privateKey) {
    const decrypted = crypto.privateDecrypt(privateKey, encryptedContent);
    return decrypted;
}

// 上传加密后的文件
async function uploadEncryptedFile(filePath) {
    try {
        const encryptedContent = encryptFile(filePath, platFormPublicKey);

        const command = new PutObjectCommand({
            Bucket: "archivesa",
            Key: "EncryptedFile",
            Body: encryptedContent
        });

        const data = await s3Client.send(command);
        console.log('Encrypted file uploaded successfully:', data);

        // 下载加密后的文件
        const getObjectCommand = new GetObjectCommand({
            Bucket: "archivesa",
            Key: "EncryptedFile"
        });
        const downloadedData = await s3Client.send(getObjectCommand);
        const downloadedContent = await streamToBuffer(downloadedData.Body);

        // 解密下载的文件
        const decryptedContent = decryptFile(downloadedContent, platFormPrivateKey);

        // 打印解密后的结果并保存解密后的文件
        console.log('Decrypted content:', decryptedContent.toString());
        fs.writeFileSync('DecryptedFile.txt', decryptedContent);
        console.log('Decrypted file saved successfully.');
    } catch (error) {
        console.error('Error:', error);
    }
}

// 将流转换为缓冲区
function streamToBuffer(stream) {
    return new Promise((resolve, reject) => {
        const buffers = [];
        stream.on('data', (chunk) => buffers.push(chunk));
        stream.on('end', () => resolve(Buffer.concat(buffers)));
        stream.on('error', reject);
    });
}

// 调用函数并指定要加密和上传的文件路径
const filePath = 'test.txt'; // 替换为实际文件路径
uploadEncryptedFile(filePath);
