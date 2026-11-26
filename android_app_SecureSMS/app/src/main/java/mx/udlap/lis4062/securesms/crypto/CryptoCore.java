package mx.udlap.lis4062.securesms.crypto;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Pure-Java cryptographic core shared by the Android app and the desktop benchmark.
 * It has NO Android dependencies, so the exact same code is measured on both platforms.
 *
 * RSA : RSA/ECB/OAEPWithSHA-1AndMGF1Padding, the message is split into blocks of (k - 42) bytes,
 *       every ciphertext block is exactly k bytes (k = modulus length in bytes), so the receiver
 *       can split the ciphertext without separators (fixed block size, as in Bodur and Kara [1]).
 * ECC : ECIES-style hybrid scheme (ECDH + KDF + AES-128-GCM), as recommended in [3] because ECC does
 *       not encrypt directly. Ephemeral public key is sent in COMPRESSED form to save SMS space.
 */
public final class CryptoCore {

    private CryptoCore() { }

    public static final String RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    /** OAEP overhead with SHA-1: 2*hLen + 2 = 42 bytes. */
    public static final int OAEP_SHA1_OVERHEAD = 42;
    private static final SecureRandom RNG = new SecureRandom();

    // ------------------------------------------------------------------ RSA

    public static KeyPair generateRsa(int bits) throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(bits, RNG);
        return kpg.generateKeyPair();
    }

    public static int rsaModulusBytes(PublicKey pub) {
        return (((RSAPublicKey) pub).getModulus().bitLength() + 7) / 8;
    }

    /** Max plaintext bytes per RSA-OAEP block. */
    public static int rsaMaxBlock(int modulusBytes) {
        return modulusBytes - OAEP_SHA1_OVERHEAD;
    }

    public static byte[] rsaEncrypt(PublicKey pub, byte[] plain) throws GeneralSecurityException {
        int k = rsaModulusBytes(pub);
        int max = rsaMaxBlock(k);
        int blocks = Math.max(1, (plain.length + max - 1) / max);
        byte[] out = new byte[blocks * k];
        Cipher c = Cipher.getInstance(RSA_TRANSFORMATION);
        for (int i = 0; i < blocks; i++) {
            int from = i * max;
            int len = Math.min(max, plain.length - from);
            c.init(Cipher.ENCRYPT_MODE, pub, RNG);
            byte[] ct = c.doFinal(plain, from, Math.max(len, 0));
            // left-pad (doFinal always returns k bytes for OAEP, but be defensive)
            System.arraycopy(ct, 0, out, i * k + (k - ct.length), ct.length);
        }
        return out;
    }

    public static byte[] rsaDecrypt(PrivateKey priv, int modulusBytes, byte[] ct) throws GeneralSecurityException {
        if (ct.length % modulusBytes != 0) throw new GeneralSecurityException("Bad RSA ciphertext length");
        int blocks = ct.length / modulusBytes;
        Cipher c = Cipher.getInstance(RSA_TRANSFORMATION);
        byte[] buf = new byte[blocks * rsaMaxBlock(modulusBytes)];
        int pos = 0;
        for (int i = 0; i < blocks; i++) {
            c.init(Cipher.DECRYPT_MODE, priv);
            byte[] pt = c.doFinal(ct, i * modulusBytes, modulusBytes);
            System.arraycopy(pt, 0, buf, pos, pt.length);
            pos += pt.length;
        }
        return Arrays.copyOf(buf, pos);
    }

    // ------------------------------------------------------------------ ECC (ECIES)

    /** Supported NIST prime curves. code = short id used on the wire. */
    public enum Curve {
        P224("secp224r1", "224", 112),
        P256("secp256r1", "256", 128),
        P384("secp384r1", "384", 192),
        P521("secp521r1", "521", 256);

        public final String stdName;
        public final String code;
        public final int securityBits;

        Curve(String stdName, String code, int securityBits) {
            this.stdName = stdName;
            this.code = code;
            this.securityBits = securityBits;
        }

        public String label() { return "ECC P-" + code; }

        public static Curve fromCode(String code) {
            for (Curve c : values()) if (c.code.equals(code)) return c;
            throw new IllegalArgumentException("Unknown curve " + code);
        }
    }

    private static final Map<Curve, ECParameterSpec> PARAMS = new HashMap<>();

    public static boolean isCurveSupported(Curve curve) {
        try {
            params(curve);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static synchronized ECParameterSpec params(Curve curve) throws GeneralSecurityException {
        ECParameterSpec p = PARAMS.get(curve);
        if (p == null) {
            p = ((ECPublicKey) generateEc(curve).getPublic()).getParams();
            PARAMS.put(curve, p);
        }
        return p;
    }

    public static KeyPair generateEc(Curve curve) throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec(curve.stdName), RNG);
        return kpg.generateKeyPair();
    }

    static int fieldBytes(ECParameterSpec p) {
        return (p.getCurve().getField().getFieldSize() + 7) / 8;
    }

    /** SEC 1 compressed point: 0x02/0x03 || X. */
    public static byte[] compress(ECPublicKey pub) {
        ECPoint w = pub.getW();
        int n = fieldBytes(pub.getParams());
        byte[] out = new byte[n + 1];
        out[0] = (byte) (w.getAffineY().testBit(0) ? 0x03 : 0x02);
        byte[] x = unsigned(w.getAffineX(), n);
        System.arraycopy(x, 0, out, 1, n);
        return out;
    }

    public static ECPublicKey decompress(Curve curve, byte[] enc) throws GeneralSecurityException {
        ECParameterSpec ps = params(curve);
        EllipticCurve ec = ps.getCurve();
        BigInteger p = ((ECFieldFp) ec.getField()).getP();
        int n = fieldBytes(ps);
        if (enc.length != n + 1 || (enc[0] != 2 && enc[0] != 3)) {
            throw new GeneralSecurityException("Bad compressed point");
        }
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(enc, 1, enc.length));
        BigInteger rhs = x.pow(3).add(ec.getA().multiply(x)).add(ec.getB()).mod(p);
        BigInteger y = sqrtMod(rhs, p);
        if (y.testBit(0) != (enc[0] == 3)) y = p.subtract(y);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return (ECPublicKey) kf.generatePublic(new ECPublicKeySpec(new ECPoint(x, y), ps));
    }

    /** Tonelli-Shanks modular square root (p odd prime). */
    static BigInteger sqrtMod(BigInteger a, BigInteger p) throws GeneralSecurityException {
        BigInteger one = BigInteger.ONE, two = BigInteger.valueOf(2);
        if (a.signum() == 0) return BigInteger.ZERO;
        if (!a.modPow(p.subtract(one).shiftRight(1), p).equals(one)) {
            throw new GeneralSecurityException("Point not on curve");
        }
        if (p.testBit(1)) { // p = 3 mod 4
            return a.modPow(p.add(one).shiftRight(2), p);
        }
        BigInteger q = p.subtract(one);
        int s = 0;
        while (!q.testBit(0)) { q = q.shiftRight(1); s++; }
        BigInteger z = two;
        while (z.modPow(p.subtract(one).shiftRight(1), p).equals(one)) z = z.add(one);
        BigInteger m = BigInteger.valueOf(s);
        BigInteger c = z.modPow(q, p);
        BigInteger t = a.modPow(q, p);
        BigInteger r = a.modPow(q.add(one).shiftRight(1), p);
        while (!t.equals(one)) {
            int i = 0;
            BigInteger tt = t;
            while (!tt.equals(one)) { tt = tt.multiply(tt).mod(p); i++; }
            BigInteger b = c.modPow(one.shiftLeft(m.intValue() - i - 1), p);
            m = BigInteger.valueOf(i);
            c = b.multiply(b).mod(p);
            t = t.multiply(c).mod(p);
            r = r.multiply(b).mod(p);
        }
        return r;
    }

    /** ANSI X9.63 KDF with SHA-256 -> 16-byte AES key + 12-byte GCM nonce. */
    private static byte[][] kdf(byte[] z, byte[] ephCompressed) throws GeneralSecurityException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(z);
        md.update(new byte[]{0, 0, 0, 1});
        md.update(ephCompressed);
        md.update("LIS4062-SMS-ECIES".getBytes(StandardCharsets.US_ASCII));
        byte[] h = md.digest();
        return new byte[][]{Arrays.copyOfRange(h, 0, 16), Arrays.copyOfRange(h, 16, 28)};
    }

    /**
     * ECIES encrypt: output = ephemeralPub(compressed) || AES-GCM(ciphertext || 16-byte tag).
     * A fresh ephemeral key per message makes the derived (key, nonce) pair unique, so the nonce
     * does not need to be transmitted (saves 12 bytes in every SMS).
     */
    public static byte[] eciesEncrypt(Curve curve, ECPublicKey recipient, byte[] plain) throws GeneralSecurityException {
        KeyPair eph = generateEc(curve);
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(eph.getPrivate());
        ka.doPhase(recipient, true);
        byte[] z = ka.generateSecret();
        byte[] ephC = compress((ECPublicKey) eph.getPublic());
        byte[][] kn = kdf(z, ephC);
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kn[0], "AES"), new GCMParameterSpec(128, kn[1]));
        byte[] ct = aes.doFinal(plain);
        byte[] out = new byte[ephC.length + ct.length];
        System.arraycopy(ephC, 0, out, 0, ephC.length);
        System.arraycopy(ct, 0, out, ephC.length, ct.length);
        return out;
    }

    public static byte[] eciesDecrypt(Curve curve, PrivateKey priv, byte[] data) throws GeneralSecurityException {
        int n = fieldBytes(params(curve)) + 1;
        byte[] ephC = Arrays.copyOfRange(data, 0, n);
        ECPublicKey eph = decompress(curve, ephC);
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(priv);
        ka.doPhase(eph, true);
        byte[] z = ka.generateSecret();
        byte[][] kn = kdf(z, ephC);
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kn[0], "AES"), new GCMParameterSpec(128, kn[1]));
        return aes.doFinal(data, n, data.length - n);
    }

    // ------------------------------------------------------------------ wire format (SMS text)
    //  Encrypted RSA message : R1:<base64(ciphertext blocks)>
    //  Encrypted ECC message : E1:<curve>:<base64(eph || ct || tag)>
    //  Public RSA key share  : K1:R:<base64(X.509 SubjectPublicKeyInfo)>
    //  Public ECC key share  : K1:E:<curve>:<base64(compressed point)>
    //  Base64 and ':' belong to the GSM 03.38 basic 7-bit alphabet ('|' does not: it costs 2 septets),
    //  so every SMS segment holds 160 chars (153 per part when concatenated).

    public static final String RSA_PREFIX = "R1:";
    public static final String ECC_PREFIX = "E1:";
    public static final String KEY_PREFIX = "K1:";

    public static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }

    public static byte[] unb64(String s) { return Base64.getDecoder().decode(s.trim()); }

    public static String wrapRsa(PublicKey recipient, String message) throws GeneralSecurityException {
        return RSA_PREFIX + b64(rsaEncrypt(recipient, message.getBytes(StandardCharsets.UTF_8)));
    }

    public static String wrapEcc(Curve curve, ECPublicKey recipient, String message) throws GeneralSecurityException {
        return ECC_PREFIX + curve.code + ":" + b64(eciesEncrypt(curve, recipient, message.getBytes(StandardCharsets.UTF_8)));
    }

    public static String rsaKeyShare(PublicKey pub) { return KEY_PREFIX + "R:" + b64(pub.getEncoded()); }

    public static String eccKeyShare(Curve curve, ECPublicKey pub) {
        return KEY_PREFIX + "E:" + curve.code + ":" + b64(compress(pub));
    }

    public static PublicKey rsaPublicFromB64(String b64) throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(unb64(b64)));
    }

    public static PrivateKey rsaPrivateFromB64(String b64) throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(unb64(b64)));
    }

    public static PrivateKey ecPrivateFromB64(String b64) throws GeneralSecurityException {
        return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(unb64(b64)));
    }

    public static ECPublicKey ecPublicFromB64(String b64) throws GeneralSecurityException {
        return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(unb64(b64)));
    }

    /** Number of SMS segments for a GSM-7 text (160 chars single, 153 per concatenated part). */
    public static int smsSegments(int chars) {
        if (chars <= 160) return 1;
        return (chars + 152) / 153;
    }

    /** Short SHA-256 fingerprint of a public key, for verifying keys by voice/in person. */
    public static String fingerprint(byte[] encodedPub) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(encodedPub);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8; i++) {
                if (i > 0 && i % 2 == 0) sb.append(':');
                sb.append(String.format("%02X", h[i]));
            }
            return sb.toString();
        } catch (GeneralSecurityException e) {
            return "?";
        }
    }

    public static String rsaSecurityLevel(int bits) {
        switch (bits) {
            case 512: return "<64 (broken)";
            case 1024: return "80";
            case 2048: return "112";
            case 3072: return "128";
            case 4096: return "~140";
            case 7680: return "192";
            case 15360: return "256";
            default: return "?";
        }
    }

    private static byte[] unsigned(BigInteger v, int len) {
        byte[] b = v.toByteArray();
        if (b.length == len) return b;
        byte[] out = new byte[len];
        if (b.length > len) System.arraycopy(b, b.length - len, out, 0, len);
        else System.arraycopy(b, 0, out, len - b.length, b.length);
        return out;
    }
}
