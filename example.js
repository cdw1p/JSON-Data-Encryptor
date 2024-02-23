const encryptor = require('./public/js/encryptor.js')

;(async () => {
  try {
    // Initialize Data
    const mySecretKey = `uSmGAtpKdwU9eOf1Haw2IlIhFbzWwOvi` // Must be 32 characters
    const fileJSON = require('./public/data.json')

    // Encrypt Data
    const encryptedData = encryptor.encrypt(mySecretKey, JSON.stringify(fileJSON))
    console.log({ encryptedData })

    // Decrypt Data
    const decryptedData = encryptor.decrypt(mySecretKey, encryptedData)
    console.log({ decryptedData })
  } catch (err) {
    console.error(`ERROR: ${err.message}`)
  }
})()