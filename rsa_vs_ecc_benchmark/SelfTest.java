import mx.udlap.lis4062.securesms.crypto.CryptoCore;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPublicKey;

/** Functional tests: round trips, wire format, key shares, point compression on every curve. */
public class SelfTest {
    static int fails = 0;

    static void check(boolean c, String what) {
        System.out.println((c ? "PASS " : "FAIL ") + what);
        if (!c) fails++;
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("bc")) {
            // Bouncy Castle provides secp224r1 (p = 1 mod 4) on desktop -> exercises Tonelli-Shanks path
            Security.insertProviderAt((java.security.Provider) Class.forName(
                    "org.bouncycastle.jce.provider.BouncyCastleProvider").getDeclaredConstructor().newInstance(), 1);
        }
        String msg = "Meet at the library at 5 pm. Bring the USB drive. ¿Listo? ñ€";

        for (int bits : new int[]{1024, 2048, 3072}) {
            KeyPair kp = CryptoCore.generateRsa(bits);
            String wire = CryptoCore.wrapRsa(kp.getPublic(), msg);
            byte[] ct = CryptoCore.unb64(wire.substring(3));
            String back = new String(CryptoCore.rsaDecrypt(kp.getPrivate(),
                    CryptoCore.rsaModulusBytes(kp.getPublic()), ct), "UTF-8");
            check(back.equals(msg), "RSA-" + bits + " round trip (" + wire.length() + " chars)");
            String share = CryptoCore.rsaKeyShare(kp.getPublic());
            PublicKey parsed = CryptoCore.rsaPublicFromB64(share.substring(5));
            check(parsed.equals(kp.getPublic()), "RSA-" + bits + " key share parse (" + share.length() + " chars)");
            // multi-block
            String longMsg = "x".repeat(1000);
            byte[] ct2 = CryptoCore.rsaEncrypt(kp.getPublic(), longMsg.getBytes("UTF-8"));
            check(new String(CryptoCore.rsaDecrypt(kp.getPrivate(), bits / 8, ct2), "UTF-8").equals(longMsg),
                    "RSA-" + bits + " multi-block 1000 chars -> " + ct2.length / (bits / 8) + " blocks");
        }

        for (CryptoCore.Curve c : CryptoCore.Curve.values()) {
            if (!CryptoCore.isCurveSupported(c)) {
                System.out.println("SKIP " + c.label() + " (provider lacks curve)");
                continue;
            }
            for (int i = 0; i < 50; i++) { // many random keys -> both parities, sqrt path
                KeyPair kp = CryptoCore.generateEc(c);
                ECPublicKey pub = (ECPublicKey) kp.getPublic();
                ECPublicKey round = CryptoCore.decompress(c, CryptoCore.compress(pub));
                if (!round.getW().equals(pub.getW())) { check(false, c.label() + " compression"); break; }
            }
            check(true, c.label() + " point compress/decompress x50");
            KeyPair kp = CryptoCore.generateEc(c);
            String wire = CryptoCore.wrapEcc(c, (ECPublicKey) kp.getPublic(), msg);
            String b64 = wire.substring(wire.indexOf(':', 3) + 1);
            String back = new String(CryptoCore.eciesDecrypt(c, kp.getPrivate(), CryptoCore.unb64(b64)), "UTF-8");
            check(back.equals(msg), c.label() + " ECIES round trip (" + wire.length() + " chars)");
            // tamper detection (GCM tag)
            byte[] ct = CryptoCore.unb64(b64);
            ct[ct.length - 1] ^= 1;
            boolean rejected;
            try { CryptoCore.eciesDecrypt(c, kp.getPrivate(), ct); rejected = false; }
            catch (Exception e) { rejected = true; }
            check(rejected, c.label() + " tampered ciphertext rejected");
            String share = CryptoCore.eccKeyShare(c, (ECPublicKey) kp.getPublic());
            check(share.length() < 160, c.label() + " key share fits in 1 SMS (" + share.length() + " chars)");
        }
        System.out.println(fails == 0 ? "ALL TESTS PASSED" : fails + " FAILURES");
        System.exit(fails == 0 ? 0 : 1);
    }
}
