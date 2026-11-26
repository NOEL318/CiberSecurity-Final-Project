# Secure SMS (RSA / ECC) — LIS4062 Final Project

Android app (Java, no third-party libraries) that sends SMS encrypted end to end with
**RSA-OAEP** or **ECIES (ECDH + AES-128-GCM)** and compares both algorithms **at the receiver**.

## Build and run
1. Open this folder in **Android Studio** (File > Open > `FinalProjectSMS`). Accept the Gradle sync
   (it downloads Gradle 8.9 and Android Gradle Plugin 8.7.3; if Studio offers an AGP upgrade, accept it).
2. Requires Android SDK 34. Minimum device: Android 8.0 (API 26).
3. Run on a phone or emulator. Grant the **SMS permissions** when asked.

### Testing with two emulators (no SIM, no cost)
Start two emulators from Device Manager. Their phone numbers are their console ports: **5554** and **5556**.
In emulator 5554 type `5556` as contact number (and vice versa); SMS between them are delivered locally.

## Demo flow
1. Both devices: *Generate my RSA + ECC key pairs* (e.g. RSA-2048 and P-256).
2. Type the other device's number, press *Send my public keys by SMS* on both. Compare the fingerprints.
   (Alternative: *Paste contact key* with the `K1:...` text.)
3. Choose RSA or ECC, write a message, *Preview ciphertext* / *Encrypt and send SMS*.
4. Receiver: *Inbox / decrypt* → tap the message → plaintext + decryption time → *Compare RSA vs ECC*.
5. *RSA vs ECC benchmark*: *Run key-size test* (140 chars) and *Run length sweep*, then *Share CSV*.

## Code map
| File | Role |
|---|---|
| `crypto/CryptoCore.java` | RSA-OAEP blocks, ECIES, point compression (Tonelli–Shanks), wire format |
| `crypto/Benchmark.java` | Timing of key generation / encryption / decryption, sizes, CSV |
| `MainActivity.java` | Keys, key exchange, compose, encrypt, send |
| `SmsReceiver.java` | Receives `K1:` key shares and `R1:` / `E1:` encrypted messages |
| `InboxActivity.java` | Decrypts at the receiver, per-message RSA vs ECC comparison |
| `BenchmarkActivity.java` | Full on-device benchmark |
| `KeyRepository.java`, `SmsSender.java` | Storage and SMS sending |

## SMS formats
```
R1:<base64 RSA-OAEP blocks>          encrypted with RSA
E1:<224|256|384|521>:<base64>        ECIES: compressed ephemeral key || AES-GCM ciphertext || tag
K1:R:<base64 X.509 public key>       RSA public key share
K1:E:<curve>:<base64 point>          ECC public key share (compressed point)
```

## Desktop benchmark (same crypto code)
```
cd desktop-bench
javac -d out ../FinalProjectSMS/app/src/main/java/mx/udlap/lis4062/securesms/crypto/*.java BenchmarkMain.java SelfTest.java
java -cp out SelfTest
java -cp out BenchmarkMain . keysonly     # -> bench_keysizes.csv
java -cp out BenchmarkMain . sweeponly    # -> bench_msglen.csv
```
