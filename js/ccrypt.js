/*
 * simple (to use) plaintext encryption and decryption functions
 * the format allows interchange with the jsencryptAES and jsdecryptAES
 * functions in jscrypt.c
 *
 * These functions depend on the experimental subtlecrypt and TextEncoder
 * functions and have only been tested on Firefox and Chrome.
 */

/* exported encryptAES() */
async function encryptAES (plaintext) {
  var iv = window.crypto.getRandomValues(new Uint8Array(16))
  const alg = { name: 'AES-CBC', iv: iv }
  const pw = document.getElementById('key').value
  const pwUtf8 = new TextEncoder().encode(pw)
  const pwHash = await window.crypto.subtle.digest('SHA-256', pwUtf8)
  const key = await window.crypto.subtle.importKey('raw', pwHash, alg, false, ['encrypt'])
  const ptUint8 = new TextEncoder().encode(plaintext)
  const ctBuffer = await window.crypto.subtle.encrypt(alg, key, ptUint8)
  const ctArray = Array.from(new Uint8Array(ctBuffer))
  const ctivArray = Array.from(iv).concat(ctArray)
  const ctStr = ctivArray.map(byte => String.fromCharCode(byte)).join('')
  return window.btoa(ctStr)
}

async function decryptAES (ciphertext) {
  const ctivStr = window.atob(ciphertext)
  const ctivUint8 = new Uint8Array(ctivStr.match(/[\s\S]/g).map(ch => ch.charCodeAt(0)))
  const iv = ctivUint8.slice(0, 16)
  const alg = { name: 'AES-CBC', iv: iv }
  const pw = document.getElementById('key').value
  const pwUtf8 = new TextEncoder().encode(pw)
  const pwHash = await window.crypto.subtle.digest('SHA-256', pwUtf8)
  const key = await window.crypto.subtle.importKey('raw', pwHash, alg, false, ['decrypt'])
  const ctUint8 = ctivUint8.slice(16)
  const plainBuffer = await window.crypto.subtle.decrypt(alg, key, ctUint8)
  const plaintext = new TextDecoder().decode(plainBuffer)
  return plaintext
}
