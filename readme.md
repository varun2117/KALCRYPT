

### README: Multilingual Substitution and Encryption Framework

---

#### **Overview**
This project provides a robust encryption framework utilizing multiple layers of obfuscation and encryption:

1. **Multilingual Substitution**: Substitutes characters with symbols from a diverse pool of non-English scripts for enhanced obfuscation.
2. **English Substitution**: Maps multilingual symbols to random English alphanumeric characters.
3. **AES Encryption with RSA Key Wrapping**: Protects the substituted text using AES encryption, with the AES key securely encrypted using RSA.

---

#### **Features**
- **Multilingual Obfuscation**: Substitutes characters with symbols from a variety of language scripts.
- **Layered Security**: Combines substitution methods with strong AES and RSA encryption.
- **Key Management**: Ensures secure AES key transfer using RSA public/private key pairs.

---

#### **Dependencies**
- Python >= 3.6
- `cryptography` library (Install via `pip install cryptography`)

---

#### **Usage**
1. **Encrypting a Message**
   - Input your message.
   - The framework performs the following steps:
     1. **Multilingual Substitution**: Maps characters in the input message to symbols from the multilingual character pool.
     2. **English Substitution**: Maps these multilingual symbols to random English alphanumeric characters.
     3. **AES Encryption**: Encrypts the substituted message using AES with a password-derived key.
     4. **RSA Key Wrapping**: Encrypts the AES key using RSA public-key encryption.

2. **Decrypting a Message**
   - The framework reverses the process:
     1. **RSA Key Unwrapping**: Decrypts the AES key using the RSA private key.
     2. **AES Decryption**: Recovers the substituted message.
     3. **Reverse English Substitution**: Maps English alphanumeric characters back to the multilingual symbols.
     4. **Reverse Multilingual Substitution**: Recovers the original plaintext message.

---

#### **Example Workflow**
1. **Input**: 
   ```plaintext
   Hello, World!
   ```

2. **Encryption Process**:
   - Multilingual Substitution: `Σφχξ, ΛΨΠδ!`
   - English Substitution: `X7TgY1pQr3`
   - AES + RSA Encryption: `Base64-encoded ciphertext`

3. **Decryption Process**:
   - Reverse AES + RSA: `X7TgY1pQr3`
   - Reverse English Substitution: `Σφχξ, ΛΨΠδ!`
   - Reverse Multilingual Substitution: `Hello, World!`

4. **Output**:
   ```plaintext
   Hello, World!
   ```

---

#### **API Methods**
- **Encryption**
  - `multilingual_substitution(message)`: Substitutes characters using a multilingual character pool.
  - `english_substitution(multilingual_message)`: Maps multilingual symbols to English characters.
  - `aes_encrypt(data, password, public_key)`: Encrypts data using AES and secures the AES key with RSA.

- **Decryption**
  - `aes_decrypt(encrypted_data, password, private_key)`: Decrypts AES-encrypted data and retrieves the AES key.
  - `reverse_english_substitution(english_message, english_map)`: Reverses English character substitution.
  - `reverse_multilingual_substitution(multilingual_message, key_map)`: Reverses multilingual substitution.

---

#### **Limitations**
- Multilingual substitution relies on a predefined character pool. It may not handle all scripts or custom requirements.
- Substitution layers add computational overhead.

---

I was pushed by sdlc agent

#### **License**
This project is open-source under the MIT License. Contributions and improvements are welcome!
