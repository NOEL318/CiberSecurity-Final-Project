package mx.udlap.lis4062.securesms.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

/**
 * RSA vs ECC benchmark executed at the RECEIVER (the device that owns the private key).
 * Pure Java: used by the Android BenchmarkActivity and by the desktop BenchmarkMain.
 */
public final class Benchmark {

    public interface Progress { void onProgress(String line); }

    public static final class Result {
        public String scheme;        // "RSA-2048" or "ECC P-256"
        public String family;        // "RSA" or "ECC"
        public int keyBits;          // modulus bits or curve bits
        public String securityBits;  // NIST equivalent security level
        public int messageChars;
        public double keyGenMs;      // mean key-pair generation time
        public double encMs;         // mean encryption time
        public double decMs;         // mean decryption time
        public double encSd, decSd;  // standard deviations
        public int cipherBytes;      // raw ciphertext bytes
        public int smsChars;         // characters of the SMS payload (prefix + Base64)
        public int smsSegments;      // GSM-7 segments
        public int publicKeyBytes;   // bytes needed to share the public key
        public boolean verified;     // decrypt(encrypt(m)) == m for every iteration

        public static String csvHeader() {
            return "scheme,family,key_bits,security_bits,message_chars,keygen_ms,enc_ms,enc_sd,dec_ms,dec_sd,"
                    + "cipher_bytes,sms_chars,sms_segments,public_key_bytes,verified";
        }

        public String toCsv() {
            return String.format(java.util.Locale.US, "%s,%s,%d,%s,%d,%.3f,%.4f,%.4f,%.4f,%.4f,%d,%d,%d,%d,%b",
                    scheme, family, keyBits, securityBits, messageChars, keyGenMs, encMs, encSd, decMs, decSd,
                    cipherBytes, smsChars, smsSegments, publicKeyBytes, verified);
        }

        public String pretty() {
            return String.format(java.util.Locale.US,
                    "%-10s sec=%-5s msg=%4d  keygen=%9.2f ms  enc=%8.3f ms  dec=%8.3f ms  ct=%4d B  sms=%4d ch/%d seg%s",
                    scheme, securityBits, messageChars, keyGenMs, encMs, decMs, cipherBytes, smsChars, smsSegments,
                    verified ? "" : "  [VERIFY FAILED]");
        }
    }

    private Benchmark() { }

    public static String randomMessage(int chars, long seed) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,";
        Random r = new Random(seed);
        StringBuilder sb = new StringBuilder(chars);
        for (int i = 0; i < chars; i++) sb.append(alphabet.charAt(r.nextInt(alphabet.length())));
        return sb.toString();
    }

    private static double mean(double[] v) {
        double s = 0;
        for (double x : v) s += x;
        return s / v.length;
    }

    private static double sd(double[] v) {
        double m = mean(v), s = 0;
        for (double x : v) s += (x - m) * (x - m);
        return v.length > 1 ? Math.sqrt(s / (v.length - 1)) : 0;
    }

    public static Result runRsa(int bits, int msgChars, int keyGenReps, int warmup, int iters, Progress p)
            throws GeneralSecurityException {
        Result r = new Result();
        r.family = "RSA";
        r.scheme = "RSA-" + bits;
        r.keyBits = bits;
        r.securityBits = CryptoCore.rsaSecurityLevel(bits);
        r.messageChars = msgChars;

        double[] kg = new double[keyGenReps];
        KeyPair kp = null;
        for (int i = 0; i < keyGenReps; i++) {
            long t0 = System.nanoTime();
            kp = CryptoCore.generateRsa(bits);
            kg[i] = (System.nanoTime() - t0) / 1e6;
            if (p != null) p.onProgress(r.scheme + " keygen " + (i + 1) + "/" + keyGenReps);
        }
        r.keyGenMs = mean(kg);
        r.publicKeyBytes = kp.getPublic().getEncoded().length;
        int k = CryptoCore.rsaModulusBytes(kp.getPublic());

        byte[] msg = randomMessage(msgChars, 42).getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < warmup; i++) {
            CryptoCore.rsaDecrypt(kp.getPrivate(), k, CryptoCore.rsaEncrypt(kp.getPublic(), msg));
        }
        double[] enc = new double[iters], dec = new double[iters];
        boolean ok = true;
        byte[] ct = null;
        for (int i = 0; i < iters; i++) {
            long t0 = System.nanoTime();
            ct = CryptoCore.rsaEncrypt(kp.getPublic(), msg);
            long t1 = System.nanoTime();
            byte[] pt = CryptoCore.rsaDecrypt(kp.getPrivate(), k, ct);
            long t2 = System.nanoTime();
            enc[i] = (t1 - t0) / 1e6;
            dec[i] = (t2 - t1) / 1e6;
            ok &= Arrays.equals(pt, msg);
        }
        fill(r, enc, dec, ok, ct.length, CryptoCore.RSA_PREFIX.length());
        if (p != null) p.onProgress(r.pretty());
        return r;
    }

    public static Result runEcc(CryptoCore.Curve curve, int msgChars, int keyGenReps, int warmup, int iters,
                                Progress p) throws GeneralSecurityException {
        Result r = new Result();
        r.family = "ECC";
        r.scheme = curve.label();
        r.keyBits = Integer.parseInt(curve.code);
        r.securityBits = String.valueOf(curve.securityBits);
        r.messageChars = msgChars;

        double[] kg = new double[keyGenReps];
        KeyPair kp = null;
        for (int i = 0; i < keyGenReps; i++) {
            long t0 = System.nanoTime();
            kp = CryptoCore.generateEc(curve);
            kg[i] = (System.nanoTime() - t0) / 1e6;
        }
        r.keyGenMs = mean(kg);
        r.publicKeyBytes = CryptoCore.compress((ECPublicKey) kp.getPublic()).length;
        ECPublicKey pub = (ECPublicKey) kp.getPublic();

        byte[] msg = randomMessage(msgChars, 42).getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < warmup; i++) {
            CryptoCore.eciesDecrypt(curve, kp.getPrivate(), CryptoCore.eciesEncrypt(curve, pub, msg));
        }
        double[] enc = new double[iters], dec = new double[iters];
        boolean ok = true;
        byte[] ct = null;
        for (int i = 0; i < iters; i++) {
            long t0 = System.nanoTime();
            ct = CryptoCore.eciesEncrypt(curve, pub, msg);
            long t1 = System.nanoTime();
            byte[] pt = CryptoCore.eciesDecrypt(curve, kp.getPrivate(), ct);
            long t2 = System.nanoTime();
            enc[i] = (t1 - t0) / 1e6;
            dec[i] = (t2 - t1) / 1e6;
            ok &= Arrays.equals(pt, msg);
        }
        fill(r, enc, dec, ok, ct.length, (CryptoCore.ECC_PREFIX + curve.code + ":").length());
        if (p != null) p.onProgress(r.pretty());
        return r;
    }

    private static void fill(Result r, double[] enc, double[] dec, boolean ok, int ctLen, int prefixLen) {
        r.encMs = mean(enc);
        r.decMs = mean(dec);
        r.encSd = sd(enc);
        r.decSd = sd(dec);
        r.verified = ok;
        r.cipherBytes = ctLen;
        r.smsChars = prefixLen + CryptoCore.b64(new byte[ctLen]).length();
        r.smsSegments = CryptoCore.smsSegments(r.smsChars);
    }

    /** Full suite at one message length. Unsupported curves are skipped and reported. */
    public static List<Result> runSuite(int[] rsaBits, int msgChars, int keyGenReps, int warmup, int iters,
                                        Progress p) throws GeneralSecurityException {
        List<Result> out = new ArrayList<>();
        for (int bits : rsaBits) {
            int reps = bits >= 4096 ? Math.max(1, keyGenReps / 3) : keyGenReps;
            out.add(runRsa(bits, msgChars, reps, warmup, iters, p));
        }
        for (CryptoCore.Curve c : CryptoCore.Curve.values()) {
            if (!CryptoCore.isCurveSupported(c)) {
                if (p != null) p.onProgress(c.label() + " not supported by this platform's provider - skipped");
                continue;
            }
            out.add(runEcc(c, msgChars, keyGenReps, warmup, iters, p));
        }
        return out;
    }
}
