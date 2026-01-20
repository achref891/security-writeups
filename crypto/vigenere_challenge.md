# Cryptography Lab Write-Up: The Vigenère Cipher

## A Journey into Polyalphabetic Substitution

---

### Mission Brief

Our first objective was to decrypt a secret message, armed with only the ciphertext and a single keyword. This classic scenario points towards a polyalphabetic substitution cipher, and our investigation led us to the venerable Vigenère cipher.

**Ciphertext:** `rgnoDVD{O0NU_WQ3_G1G3O3T3_A1AH3S_cc82272b}`
**Keyword:** `CYLAB`

### Cracking the Code

The Vigenère cipher, a step up from the simple Caesar cipher, uses a keyword to apply a series of different shifts to the plaintext. Each letter of the keyword determines the shift amount, creating a more complex and historically resilient form of encryption.

To unravel this, we turned to Python to automate the decryption process. The script systematically applies the inverse shift for each character based on the repeating keyword `CYLAB`.

> **Fun Fact:** The Vigenère cipher was once considered "le chiffrage indéchiffrable" (French for "the indecipherable cipher").

#### The Decryption Tool

Here is the Python script engineered for this task:

```python
#!/usr/bin/env python3

def vigenere_decrypt(ciphertext, key):
    key = key.upper()
    decrypted_text = ""
    key_index = 0
    for char in ciphertext:
        if 'a' <= char <= 'z':
            shift = ord(key[key_index % len(key)]) - ord('A')
            decrypted_char = chr(((ord(char) - ord('a') - shift + 26) % 26) + ord('a'))
            key_index += 1
        elif 'A' <= char <= 'Z':
            shift = ord(key[key_index % len(key)]) - ord('A')
            decrypted_char = chr(((ord(char) - ord('A') - shift + 26) % 26) + ord('A'))
            key_index += 1
        else:
            decrypted_char = char
        decrypted_text += decrypted_char
    return decrypted_text

ciphertext = "rgnoDVD{O0NU_WQ3_G1G3O3T3_A1AH3S_cc82272b}"
key = "CYLAB"
decrypted_message = vigenere_decrypt(ciphertext, key)

print(f"Decrypted message: {decrypted_message}")
```

### Mission Accomplished

Executing the script revealed the hidden message, a flag in the classic CTF format.

**Decrypted Flag:** `picoCTF{D0NT_US3_V1G3N3R3_C1PH3R_ae82272q}`

This humorous flag serves as a reminder of the cipher's place in history and its vulnerability to modern analysis.

---