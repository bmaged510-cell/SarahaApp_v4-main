import crypto from 'node:crypto';
import { ENC_KEY, IV_LENGTH } from '../../config.js';
import { log } from 'node:console';

export const encryption = async(plainText)=>{
    //(1) initialize vector
    const iv = crypto.randomBytes(IV_LENGTH) 
    const cipher = crypto.createCipheriv('aes-256-cbc' , ENC_KEY , iv)
    let encryptedData= cipher.update(plainText , "utf-8" , "hex") 
    encryptedData+= cipher.final("hex")
    console.log({iv,cipher , encryptedData});

    return `${iv.toString("hex")}::${encryptedData}` 
}

export const decryption = async (cipherText)=>{
    const [iv , encryptedData] = cipherText.split("::")
    console.log({iv , encryptedData});
    const iv_vector = Buffer.from(iv , "hex")
    console.log({iv_vector});
    
    const decipherVector = crypto.createDecipheriv("aes-256-cbc" , ENC_KEY , iv_vector)
    let plainText = decipherVector.update(encryptedData , "hex" , "utf-8") 
    plainText+=decipherVector.final("utf-8")
    return plainText
}   