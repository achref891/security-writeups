# Cryptography Lab Write-Up: The RSA Cube Root Attack

## Exploiting a Subtle Flaw in Modern Cryptography

---

### Mission Brief

The challenge presented a modern cryptographic puzzle. We were given the public parameters of an RSA encryption and tasked with decrypting the ciphertext.

**Public Parameters:**
- **N (Modulus):** A tremendously large integer.
- **e (Public Exponent):** `3`
- **c (Ciphertext):** An equally large integer.

These were extracted from the `values` file.

### Finding the Achilles' Heel

At first glance, the task seemed impossible. The security of RSA relies on the monumental difficulty of factoring the modulus `N`. Without its prime factors, the private key `d` remains elusive.

However, a critical vulnerability was spotted: the public exponent `e` was set to the small value of `3`. This opens the door for a specific line of attack.

> The **Cube Root Attack** is a known vulnerability in RSA implementations that use a small public exponent without proper message padding.

If the original message `m` was small enough that `m^3` did not exceed `N`, the modular arithmetic `c = m^3 mod N` would not "wrap around", resulting in a simple equation: `c = m^3`. Decryption, therefore, becomes a straightforward calculation of the integer cube root of `c`.

#### The Decryption Tool

We crafted a Python script to execute this attack. Lacking specialized libraries, we implemented a binary search algorithm to efficiently find the integer cube root of the massive ciphertext.

```python
#!/usr/bin/env python3

def integer_cuberoot(n):
    """
    Calculates the integer cube root of a non-negative integer n
    using binary search.
    """
    if n < 0:
        return None
    if n == 0:
        return 0
    low = 1
    high = n
    root = 1
    while low <= high:
        mid = (low + high) // 2
        if mid == 0:
            low = 1
            continue
        try:
            mid_cubed = mid * mid * mid
        except OverflowError:
            mid_cubed = float('inf')
        if mid_cubed == n:
            return mid
        elif mid_cubed < n:
            root = mid
            low = mid + 1
        else:
            high = mid - 1
    return root

def main():
    c = 570972017502631784194450516633218277941976003111543221556342590187562005279160816339875029730427788649553736779300628811299193271721106661189931996370183806282820925445893598314120710032289722102106311639862166461241881377855456826434043022583257849111465377112170858026226408596849273262655939261588254126767004557097444490754277629407557155808510093076076072241625237807761095436754785212665934837250503093646087894004680810481604256238017714319407077341703010615869343684889773379558815615343935337435437894628155614040005618549814780873776692165217996358503796407815013657830223087836886226300005918141641678331380895092329755751415812951587975893576578105573196933000547302237006049839310553220149469876224448191540688060712730021009567227440020066188186104356265075416374324633043839253143370102438975453717800082175458144988140842028275398713211594002728037219616042938774742718364126443694082721631231510105131701780747726012636466088768725514820344357055715523621362143648027363044170885031058505704
    m = integer_cuberoot(c)
    if m*m*m == c:
        try:
            message_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
            message = message_bytes.decode('utf-8')
            print(f"Decrypted message: {message}")
        except UnicodeDecodeError:
            print(f"Could not decode message as UTF-8. Raw bytes: {message_bytes}")
        except Exception as e:
            print(f"An error occurred during decoding: {e}")
    else:
        print("Cube root attack failed. m^3 != c.")

if __name__ == "__main__":
    main()
```

### Mission Accomplished

The script successfully calculated the cube root, confirming our hypothesis. The resulting integer was then decoded back into a readable string, revealing the flag.

**Decrypted Flag:** `picoCTF{e_sh0u1d_b3_lArg3r_92f4d5a5}`

This flag cleverly points out the very flaw we exploited: the public exponent `e` should indeed be larger to prevent such attacks.

---
