const crypto = require('node:crypto')

/**
 * Represents an Encryptor object used for encrypting and decrypting text.
 */
class Encryptor {
  /**
   * Creates a new instance of the Encryptor class.
   */
  constructor() {
    this.separator = '::S3CR3T:'
  }

  /**
   * Encrypts the given text using the provided encryption key.
   * @param {string} encryptionKey - The encryption key to use.
   * @param {string} textToEncrypt - The text to encrypt.
   * @returns {string} The encrypted string.
   */
  encrypt = (encryptionKey, textToEncrypt) => {
    const vector = crypto.randomBytes(16)
    const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, vector)
    const encryptedString = cipher.update(textToEncrypt)
    return `${vector.toString('hex')}${this.separator}${Buffer.concat([encryptedString, cipher.final()]).toString('hex')}`
  }

  /**
   * Decrypts an encrypted string using the provided decryption key.
   * @param {string} decryptionKey - The key used for decryption.
   * @param {string} encryptedString - The string to be decrypted.
   * @returns {string|boolean} - The decrypted string, or false if decryption fails.
   */
  decrypt = (decryptionKey, encryptedString) => {
    try {
      const parts = encryptedString.split(this.separator)
      const vector = Buffer.from(parts.shift(), 'hex')
      const encryptedText = Buffer.from(parts.join(this.separator), 'hex')
      const decipher = crypto.createDecipheriv('aes-256-cbc', decryptionKey, vector)
      const decrypted = decipher.update(encryptedText)
      return Buffer.concat([decrypted, decipher.final()]).toString()
    } catch (err) {
      throw new Error(err.message)
    }
  }
}

/**
 * Exports the Encryptor class and its static methods.
 */
module.exports = new Encryptor()