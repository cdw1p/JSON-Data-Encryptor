/**
 * Class representing an Encryptor.
 * @class
 */
class Encryptor {
  constructor() {
    this.separator = '::S3CR3T:'
  }

  /**
   * Imports a raw key and returns a Promise that resolves to the imported key.
   * @param {string} rawKey - The raw key to import.
   * @returns {Promise<CryptoKey>} A Promise that resolves to the imported key.
   */
  async importKey(rawKey) {
    const keyBuffer = this.strToArrayBuffer(rawKey)
    return await crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: 'AES-CBC', length: 256 },
      false,
      ['encrypt', 'decrypt']
    )
  }

  /**
   * Converts a string to an ArrayBuffer.
   * @param {string} str - The string to be converted.
   * @returns {ArrayBuffer} The converted ArrayBuffer.
   */
  strToArrayBuffer(str) {
    return new TextEncoder().encode(str)
  }

  /**
   * Converts an ArrayBuffer to a string.
   * @param {ArrayBuffer} buf - The ArrayBuffer to convert.
   * @returns {string} The converted string.
   */
  arrayBufferToStr(buf) {
    return new TextDecoder().decode(buf)
  }

  /**
   * Converts a hexadecimal string to an ArrayBuffer.
   * @param {string} hex - The hexadecimal string to convert.
   * @returns {ArrayBuffer} - The converted ArrayBuffer.
   */
  hexToArrayBuffer(hex) {
    return new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16))).buffer
  }

  /**
   * Converts an ArrayBuffer to a hexadecimal string.
   * @param {ArrayBuffer} buffer - The ArrayBuffer to convert.
   * @returns {string} The hexadecimal string representation of the ArrayBuffer.
   */
  arrayBufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('')
  }

  /**
   * Encrypts the given text using the provided key.
   * @param {CryptoKey} key - The encryption key.
   * @param {string} textToEncrypt - The text to be encrypted.
   * @returns {Promise<string>} - The encrypted content.
   */
  async encrypt(key, textToEncrypt) {
    const iv = crypto.getRandomValues(new Uint8Array(16))
    const encodedText = this.strToArrayBuffer(textToEncrypt)
    const encryptedContent = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv },
      key,
      encodedText
    )
    return `${this.arrayBufferToHex(iv)}${this.separator}${this.arrayBufferToHex(encryptedContent)}`
  }

  /**
   * Decrypts an encrypted string using the provided key.
   * @param {CryptoKey} key - The encryption key.
   * @param {string} encryptedString - The encrypted string to decrypt.
   * @returns {Promise<string>} - The decrypted content as a string.
   * @throws {Error} - If the encrypted data is not a string.
   */
  async decrypt(key, encryptedString) {
    if (typeof encryptedString !== 'string') {
      throw new Error('Encrypted data must be a string.')
    }
    const parts = encryptedString.split(this.separator)
    const iv = this.hexToArrayBuffer(parts.shift())
    const encryptedText = this.hexToArrayBuffer(parts.join(this.separator))
    const decryptedContent = await crypto.subtle.decrypt(
      { name: 'AES-CBC', iv },
      key,
      encryptedText
    )
    return this.arrayBufferToStr(decryptedContent)
  }
}

/**
 * Validates the input based on the specified type.
 * @param {string} type - The type of operation ('encrypt' or 'decrypt').
 * @throws {Error} If the secret key is not entered or if the data to encrypt/decrypt is not entered.
 * @throws {Error} If the data to encrypt is not a valid JSON when the type is 'encrypt'.
 * @returns {boolean} Returns true if the input is valid.
 */
function validateInput(type) {
  if (document.getElementById('secretKey').value === '') {
    throw new Error('Please enter a secret key')
  }
  if (type === 'encrypt' && document.getElementById('dataToEncrypt').value === '') {
    throw new Error('Please enter data to encrypt')
  }
  if (type === 'decrypt' && document.getElementById('dataToDecrypt').value === '') {
    throw new Error('Please enter data to decrypt')
  }
  if (type === 'encrypt') {
    try {
      JSON.parse(document.getElementById('dataToEncrypt').value)
    } catch (err) {
      throw new Error('Data to encrypt must be a valid JSON')
    }
  }
  return true
}

/**
 * Encrypts the data using a secret key and updates the encrypted data field.
 * @returns {Promise<void>} A promise that resolves when the encryption is complete.
 */
async function encryptData() {
  try {
    await validateInput('encrypt')
    const encryptor = new Encryptor()
    const secretKey = await encryptor.importKey(document.getElementById('secretKey').value)
    const dataToEncrypt = JSON.stringify(document.getElementById('dataToEncrypt').value)
    const encryptedData = await encryptor.encrypt(secretKey, dataToEncrypt)
    document.getElementById('dataToDecrypt').value = encryptedData
  } catch (err) {
    alert(`ERROR: ${err.message}`)
  }
}

/**
 * Decrypts the data using the provided secret key and updates the value of the 'dataToEncrypt' element.
 * @returns {Promise<void>} A promise that resolves when the decryption is complete.
 * @throws {Error} If there is an error during the decryption process.
 */
async function decryptData() {
  try {
    await validateInput('decrypt')
    const encryptor = new Encryptor()
    const secretKey = await encryptor.importKey(document.getElementById('secretKey').value)
    const dataToDecrypt = document.getElementById('dataToDecrypt').value
    const decryptedData = await encryptor.decrypt(secretKey, dataToDecrypt)
    document.getElementById('dataToEncrypt').value = JSON.parse(decryptedData)
  } catch (err) {
    alert(`ERROR: ${err.message}`)
  }
}