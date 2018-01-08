---
layout: page

title: Cryptography

category: infosec
see_my_category_in_header: true

permalink: /infosec/cryptography.html

published: true
---

<article class="markdown-body" markdown="1">

# Content

* TOC
{:toc}

<br>

---

Real-world cryptography is not only about crypto-algorithms, but also about protocols and key-management.

Never store passwords - store hashes

* [passwordresearch.com](http://www.passwordresearch.com/) - their aim is to consolidate the important password and authentication security research in one place.
* [Cipher security against publicly known feasible attacks](https://en.wikipedia.org/wiki/Transport_Layer_Security#Cipher)

**Studying**:

* [Cryptography tutorial](https://www.tutorialspoint.com/cryptography/index.htm)
* [Crypto 101](https://www.crypto101.io/) - crypto course
* [Practical Aspects of Modern Cryptography, Winter 2011](http://courses.cs.washington.edu/courses/csep590a/11wi/)

<br>

# Cryptography basic theory, [CryptoTermininology (ghub)](https://github.com/OpenTechFund/CryptoTermininology)

Various **cryptography problems**:

* confidentiality
* integrity
* authentification
* non-repudiation ( / repudiation)

[Kerckhoffs' principle](https://en.wikipedia.org/wiki/Kerckhoffs%27s_principle)
: A cryptosystem should be secure even if everything about the system, except the key, is public knowledge.

[Birthday problem](https://en.wikipedia.org/wiki/Birthday_problem)
: birthday paradox concerns the probability that, in a set of n {\displaystyle n} n randomly chosen people, some pair of them will have the same birthday.

    The probability reaches 100% when the number of people reaches 367. However, 99.9% probability is reached with just 70 people, and 50% probability with 23 people. These conclusions are based on the assumption that each day of the year is equally probable for a birthday.
    <br>Birthday problem is relative to ***collision problem***.

[Zero-knowledge proof](https://en.wikipedia.org/wiki/Zero-knowledge_proof) (zero-knowledge protocool)
: is a method by which one party (the prover) can prove to another party (the verifier) that a given statement is true, without conveying any information apart from the fact that the statement is indeed true (other aspect is not to reveal the fact of how statement is estimated to the outer world)<br>
    subcase: ***Zero-knowledge password proof***


[PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) (Password-Based Key Derivation Function)
: PBKDF2 is a standard for generating *derived key*, based on *password* and *salt*

    *Parameters*: pseudo-random function, number of iterations desired, length of the derived key

[Hash](https://en.wikipedia.org/wiki/Cryptographic_hash_function)
: mathematical algorithm (one-way function (infeasible to invert)) that maps data of arbitrary size to a bit string of a fixed size (a hash function).

    <br>
    *Ideal **cryptographic hash** properties*:

    * determinism: same message results in the same hash
    * it is impossible to recover message from its hash value
    * a small change to a message should change the hash value so extensively that the new hash value appears uncorrelated with the old hash value
    * it is infeasible to find two different messages with the same hash value

    Productivity:

    * fast - for calculating hashes for lots of data
    * slow - to resist bruteforce

    Digest
    : output of the hash function

    Hash-functions usage:

    * PBKDF
    * store passwords
    * integrity
    * authentication


Collision
: *computer science*: situation where some function maps two distinct inputs to the same output <br>
  *telecommunications*: situation when two nodes of a network attempt to transmit at the same time

[MAC](https://en.wikipedia.org/wiki/Message_authentication_code) (message authentication code)
: a short piece of information used to authenticate a message - checks message's *integrity* and *authenticity*.

    *Input*: message + key <br>
    *Output*: tag/authentication code
    <div class="spoiler"><div class="spoiler-title" style="background-color: transparent;" markdown="1">
    <i>General scheme:</i>
    </div><div class="spoiler-text" markdown="1">
    ![]({{ "/resources/MAC-crypto.svg" | prepend: site.baseurl }}){:width="700px"}
    </div></div>

    [HMAC](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code)
    : MAC involving a cryptographic hash function and a secret cryptographic key.

        `HMAC(K, message) = H( (K' xor opad) ∥ H( (K' xor ipad) ∥ message ))`, e.g. opad = `0x5c5c5c…5c5c`, ipad = `0x363636…3636`

        Weak HMAC configurations:

        * `MAC = H(key ∥ message)` - vulnerable to:
            
            * appending message at the end and proceed with hashing (hash usually process message block after block)
            * if attacker know message, hash can be rolled back and attacker will get `H(key)`. Attacker can now bruteforce key

        * `MAC = H(message ∥ key)` - vulnerable to:
        
            * appending message at the beginning if attacker can generate message with targeted hash value (if attacker can generate collisions)
            * if attacker know message, `H(message)` can be computed and attacker can now bruteforce key

        * `MAC = H(key1 ∥ message ∥ key2)` - exists some researches not flavourable to this method

[PRNG](https://en.wikipedia.org/wiki/Pseudorandom_number_generator) (pseudo-random number generator)
: algorithm for generating a sequence of numbers whose properties approximate the properties of sequences of random numbers.

    It is a common problem of generating PRNG using computer systems (which are deterministic)

Fingerprint
: the hash of the public key.

***Statement***: As the cryptographic key is used, it becomes obsolete.

***Statement***: Cryptography Salt purpose: Similar text (e.g. passwords) after being salt (with different salt) and hashed will result in different hash-messages. <br> This is protection from rainbow tables (a precomputed table for reversing cryptographic hash functions). Salt is not a secret (in contrary to cryptography keys and passwords).

Symmetric cryptography is faster compared to asymmetric.

<br>

## Basic algorithms

**Hashes**:

* md4, md5, sha1, sha2, sha3 (Keccak), ГОСТ (Стрибог), ...

**Symmetric cryptography**:

* [block ciphers](https://en.wikipedia.org/wiki/Block_cipher)

    * [block cipher modes](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Common_modes) (ECB, CBC, CFB, OFB, CTR, ...)

        typical block size = 64, 128 bits

    * [padding](https://en.wikipedia.org/wiki/Padding_(cryptography))

    Basic operations:

    * *substitution* - [substitution ciphers](https://en.wikipedia.org/wiki/Substitution_cipher)

        ancient examples: [substitution cipher](https://en.wikipedia.org/wiki/Substitution_cipher), [Caesar cipher](https://en.wikipedia.org/wiki/Caesar_cipher), [Polyalphabetic cipher](https://en.wikipedia.org/wiki/Polyalphabetic_cipher), [Vigenere cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher), ...

        attack method: [frequency analysis](https://en.wikipedia.org/wiki/Frequency_analysis) (can be used letters frequences, but bigram frequences is better)

    * *permutation* - [transposition ciphers](https://en.wikipedia.org/wiki/Transposition_cipher)

    attack methods: [differential cryptanalysis](https://en.wikipedia.org/wiki/Differential_cryptanalysis), [linear cryptanalysis](https://en.wikipedia.org/wiki/Linear_cryptanalysis), [integral cryptanalysis](https://en.wikipedia.org/wiki/Integral_cryptanalysis)

* [stream ciphers](https://en.wikipedia.org/wiki/Elliptic_curve_cryptography) (RC4, etc.)

    ancient examples: [One-time pad (or Шифр Вернама)](https://en.wikipedia.org/wiki/One-time_pad)

**Symmetric key exchange** (without sending key through channel):

* [Diffie-Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)

**Asymmetric cryptography**:

* [DSA](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm)
* [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
* [Elliptic-curve cryptography](https://en.wikipedia.org/wiki/Elliptic_curve_cryptography)

**Asymmetric key exchange**:

* [PKI - Public Key Infrustructure](https://en.wikipedia.org/wiki/Public_key_infrastructure)

    * [WOT - Web Of Trust](https://en.wikipedia.org/wiki/Web_of_trust)
        
        * [public key servers](https://en.wikipedia.org/wiki/Key_server_(cryptographic))
    
    * [Certificate authorities](https://en.wikipedia.org/wiki/Certificate_authority)

        *Problem*: We trust certificate authorities a lot.

**Challenge-response authentication**

*   exists lots of realization and most are broken

    <div class="spoiler"><div class="spoiler-title">
    <i>approach introduced by @SolarDesigner (???)</i>
    </div><div class="spoiler-text" markdown="1">

    Client calculates this and pass through network:
    <br> `RESP = H(H(H(PASS, SALT)), CHALLENGE) xor H(PASS, SALT)`

    Server stores `H(H(PASS, SALT))`, on receiving from client RESP, he calculates:
    <br> `H( H(   H(H(PASS, SALT))   , CHALLENGE) xor RESP)` ` = ` `H( H(   H(H(PASS, SALT))   , CHALLENGE)  xor H(   H(H(PASS, SALT))   , CHALLENGE)  xor H(PASS, SALT) ) = H( H(PASS, SALT) )` - this server may check

    </div></div>

<br>

# Cryptography features

Keys became obsolete as you use them.

<br>

# Cryptography issues

This paragraph applies to all network cryptography (e.g. wifi, ssl, etc.)

Symmetric cryptography:

- Replay attacks
- MITM
- Stream-ciphers - generate streams

    - changing bit in ciphertext will change correlated bit in cleartext

- If you obliged to use the same key several times make sure you use different IV (this is extremely important for stream ciphers, or you will get identical keystreams). <br>
    IV must be bit enough, to repeat rarely between rekeyings.

- Concatenations can play havoc with the crypto-protocol. Sometimes mixing function required.

- Oracle padding - system reaction on different type of errors must be always the same (no differences in input, no differences in time)

<br>

# Standards

* [SHS - Security Hash Standard (august 2015)](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
* [DSS - Digital Signature Standard (july 2013)](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)
* [ГОСТ Р 34.12-2015 ("Кузнечик")](https://ru.wikipedia.org/wiki/%D0%9A%D1%83%D0%B7%D0%BD%D0%B5%D1%87%D0%B8%D0%BA_(%D1%88%D0%B8%D1%84%D1%80)) - симметричное, блочное шифрование
* [ГОСТ Р 34.11-2012 ("Стрибог")](https://ru.wikipedia.org/wiki/%D0%93%D0%9E%D0%A1%D0%A2_%D0%A0_34.11-2012) - алгоритм хеширования

<br>

# Cryptography elementaries

## Common [block cipher modes](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Common_modes)


| [ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_.28ECB.29) | [CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29) | [CFB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Feedback_.28CFB.29) |
|:---:|:---:|:---:|
| ![]({{ "/resources/ECB.svg" | prepend: site.baseurl }}){:width="500px"} | ![]({{ "/resources/CBC.svg" | prepend: site.baseurl }}){:width="500px"} | ![]({{ "/resources/CFB.svg" | prepend: site.baseurl }}){:width="500px"} |
| ***Drawback***: *Same* plaintext will result in *same* ciphertext | |

| [OFB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_Feedback_.28OFB.29) | [CTR](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_.28CTR.29) |
|:---:|:---:|
| ![]({{ "/resources/OFB.svg" | prepend: site.baseurl }}){:width="500px"} | ![]({{ "/resources/CTR.svg" | prepend: site.baseurl }}){:width="500px"} |

<!--| [ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_.28ECB.29) | ![]({{ "/resources/ECB.svg" | prepend: site.baseurl }}){:width="500px"} | ***Draweback***: Same plaintext will result in the same ciphertext |
| [CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29) | ![]({{ "/resources/CBC.svg" | prepend: site.baseurl }}){:width="500px"} | |
| [CFB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Feedback_.28CFB.29) | ![]({{ "/resources/CFB.svg" | prepend: site.baseurl }}){:width="500px"} | |
| [OFB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_Feedback_.28OFB.29) | ![]({{ "/resources/OFB.svg" | prepend: site.baseurl }}){:width="500px"} | |
| [CTR](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_.28CTR.29) | ![]({{ "/resources/CTR.svg" | prepend: site.baseurl }}){:width="500px"} | |-->

Block ciphers demands some **padding** for plaintext's last block completion. Exists various type of [paddings](https://en.wikipedia.org/wiki/Padding_(cryptography)#Block_cipher_mode_of_operation).

## Diffie-Hellman

**Diffie-Hellman key exchange** - allows Alice and Bob to generate common secret key *without key transmittion*.
<br>DH is not about endpoints authentication => it can be easily MiTM-ed if there is no additional precautions.
<br>DH can be applied only if both ends is online.

![Diffie-Hellman key exchange]({{ "/resources/Diffie-Hellman.svg" | prepend: site.baseurl }}){:height="250px"} ![DH Man-in-The-Middle]({{ "/resources/DH-MITM.svg" | prepend: site.baseurl }}){:height="250px"}

<br>

## TLS handshake

| TLS handshake using X509 certificates with client authentication | TLS handshake with preshared keys |
|:---:|:---:|
| ![]({{ "/resources/TLS-handshake-with-client-auth.svg" | prepend: site.baseurl }}){:width="1500px"} | ![]({{ "/resources/TLS-handshake-preshared-keys.png" | prepend: site.baseurl }}){:width="1500px"} |

**TLS False start**:

![]({{ "/resources/TLS-false-start.jpg" | prepend: site.baseurl }}){:width="500px"}

<br>

---

# Attacks

[***Cryptographic attacks cheat sheet***](https://github.com/iSECPartners/LibTech-Auditing-Cheatsheet#appendix-b-cryptographic-attacks-cheat-sheet)

SSLv3 today is considered as insecure

* [wikipedia SSL/TLS#security](https://en.wikipedia.org/wiki/Transport_Layer_Security#Security)
* [wikipedia SSL/TLS#attacks](https://en.wikipedia.org/wiki/Transport_Layer_Security#Attacks_against_TLS.2FSSL)

MITM - man in the middle

* **sslstrip** - attack based on ***http->https redirection*** - mitm interception of http to https redirection for web-applications (user's traffic must be intercepted (e.g. arpspoof, ...))

<br>

## Hash attacks

[***Lifetimes of cryptographic hash functions***](http://valerieaurora.org/hash.html)

[***Lessons from the history of attacks on secure hash functions***](https://z.cash/technology/history-of-hash-function-attacks.html)

[Hash security](https://en.wikipedia.org/wiki/Hash_function_security_summary) (wikipedia)

[Hash parameters comparison](https://en.wikipedia.org/wiki/Comparison_of_cryptographic_hash_functions#Parameters) (wikipedia)

* **rainbow table** - a precomputed table for reversing cryptographic hash functions, usually for cracking password hashes

    remediation: [Salt](https://en.wikipedia.org/wiki/Salt_(cryptography))

* **birthday attack** - the attack depends on the higher likelihood of collisions found between random attack attempts and a fixed degree of permutations

<br>

## Protocols attacks

* **protocol downgrade**

    *Downgrade methods*:

    * MiTM exchange of chosen cipher-suites. (Last TLS versions allows to sign proposed set of cipher-suites, however actually chosen cipher suite is not signed and can be tempered with.)
    * With using of ***TLS False Start*** attacker can exchange proposed set of cipher-suites.
        <br>Client will send to server chosen cipher-suite and encoded data, server will answer with data and signature of previously sent set of cipher-suites. Client will see, that signature is wrong but the data already sent and attacker can start to decrypt weakly encrypted data.

    Named attacks:

    * **FREAK** - downgrade ssl/tls cryptrography to cipher-suites *RSA_EXPORT* - weakened version of protocol (small keys (40-, 56- bits and 512-bits for RSA)) (exists because of US historical laws). Keys of this size can be cracked in rational amount of time (512 RSA key in about 8 hours on Amazon EC2)
    * **Logjam** - downgrade ssl/tls cryptrography to cipher-suites *EXPORT_DHE* - weakened version of protocol (small Diffie-Hellman keys - 512-bits) ([weakdh.org](https://weakdh.org/))
        <br>This method demands some precomputations (about a week), afterward disclosure of DH key can be done in about a minutes.

    *Mitigation*: disable unsecure protocols on server- and client- side


* **truncation attack** - attacker can send *TCP FIN* before user's logout request and user will remain logged in. Some web-applications will show to user sign of successfull logout even if it was unsuccessfull.


* **Padding ORACLE**
    
    ![]({{ "/resources/padding-oracle.png" | prepend: site.baseurl }}){:width="1000px"}
    
    (exists various types of padding, e.g. "x x x x x 03 03 03", "x x x x x 03 02 01", "x x x x x 01 02 03", ...)

    Server-side can reveal data explaining if padding is correct in next ways:

    * return message about incorrect padding
    * check padding and if it is incorrect return error, without future processing => **Time-based Padding Oracle**

    Named attacks:

    * **POODLE** (Padding Oracle On Downgraded Legacy Encryption) (CVE-2014-3566) [poodlebleed.com](http://poodlebleed.com/)
        <br> *Mitigation*: disable SSLv3.0

<br>

* **BEAST** (Browser Exploit Against SSL/TLS) (CVE-2011-3389) - attack based on ***CBC mode***.

    If attacker can control some data in user's send-data, he can shift unknown user's data (e.g. cookies) to the border of CBC block in a way, that only one unknown symbol will remain in that block.
    Now because of CBC mode attacker can construct special data (attacker knows: 1) previous ciphertext's IV 2) previous ciphertext 3) previous clear text with one symbol to be guessed (bruteforced) ) and see how it is encrypted (output ciphertext must be equal to ciphertext of data with guessed symbol). (attacker can make a lot of requests from user's context for successfull bruteforce)
    
    In wild world these attack was not seen.

    *Mitigation*: Disable cipher-suites with CBC mode, but RC4 has security weakness too => use TLSv1.2

* **CRIME** (Compression Ratio Info-leak Made Easy) (CVE-2012-4929) - if attacker can insert data into user's requests, and data compression is enabled, then attacker can use comprassion ratio as a detector of equality between inserted data and user's private data (e.g. password, etc.). (attacker can make a lot of requests from user's context for successfull bruteforce)

    **BREACH** (Browser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext) (CVE-2014-3566) - same as CRIME (attack based on compression), but applied to particular case: HTTP protocol.

* **RC4** is insecure, because ... ???

* **HEARTBLEED** - binary vulnerability (CVE-2014-0160) (most shouted about) [heartbleed.com](http://heartbleed.com/) in OpenSSL, which enables to read random (but lot's of them) server's memory blocks

<br>

## RSA attacks

RSA by itself is secure crypto-algorithm, by if we know some data about key or plaintext, etc. Some attacks can be delivered.

* [Lattice based attacks on RSA](https://github.com/mimoo/RSA-and-LLL-attacks) - Coppersmith, Boneh Durfee
* [Processing RSA keys](https://loginroot.com/cracking-the-rsa-keys-part-1-getting-the-private-exponent/) - example of how to operate with those rsa digits

<br>

---

## Tools

* [hash-identifier](https://tools.kali.org/password-attacks/hash-identifier)
* [stompy](https://github.com/reinderien/omggawd/tree/master/stompy) - entropy verifier (randomness evaluation tool) for session cookies, XSRF tokens, OTPs, ...

<br>

* [HashPump](https://github.com/bwall/HashPump) - a tool to exploit the hash length extension attack in various hashing algorithms
* [factordb](http://factordb.com/) - online service for numbers factorization
* [morse code conversion](http://www.onlineconversion.com/morse_code.htm)
* [caesar](http://planetcalc.com/1434/) - online service for caesar cipher decrypting
* [Vigenere](http://www.cryptoclub.org/tools/cracksub_topframe.php) - online service for vigenere cipher decrypting

<br>

* **openssl**

    * [libcrypto](https://wiki.openssl.org/index.php/Libcrypto_API)
    * [licrypto EVP](https://wiki.openssl.org/index.php/EVP#Cryptographic_Operations)

<br>

* [ssdeep](https://ssdeep-project.github.io/ssdeep/) - fuzzy hashing program (in brief: similar inputs results in similar hash)
* [CrypTool](https://www.cryptool.org/en/ct1-downloads) [CrypTool 2](https://www.cryptool.org/en/ct2-downloads) - e-learning platform for cryptography and cryptanalysis
    <br> There **must be** better python libraries.

    * [cryptool-online](http://www.cryptool-online.org/index.php?option=com_content&view=article&id=47&Itemid=29&lang=en) - can code/encode online many ciphers

* [xortool](https://github.com/hellman/xortool) – guess the key length and guess the key for substitution ciphers

</article>
