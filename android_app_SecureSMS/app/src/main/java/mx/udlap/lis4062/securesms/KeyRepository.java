package mx.udlap.lis4062.securesms;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;

import mx.udlap.lis4062.securesms.crypto.CryptoCore;

/**
 * Local "key library" (Bodur and Kara [1] used an online library; here public keys are exchanged by SMS
 * and stored per phone number). Private keys live in app-private storage (MODE_PRIVATE).
 * Production apps should wrap them with the Android Keystore - see report, Section "Limitations".
 */
public final class KeyRepository {

    private static final String PREFS_KEYS = "my_keys";
    private static final String PREFS_CONTACTS = "contact_keys";
    private static final String PREFS_INBOX = "inbox";

    private final SharedPreferences keys, contacts, inbox;

    public KeyRepository(Context ctx) {
        Context app = ctx.getApplicationContext();
        keys = app.getSharedPreferences(PREFS_KEYS, Context.MODE_PRIVATE);
        contacts = app.getSharedPreferences(PREFS_CONTACTS, Context.MODE_PRIVATE);
        inbox = app.getSharedPreferences(PREFS_INBOX, Context.MODE_PRIVATE);
    }

    /** Compare phone numbers by their last 10 digits (+52 222 ... and 222 ... are the same contact). */
    public static String normalize(String phone) {
        if (phone == null) return "";
        String d = phone.replaceAll("[^0-9]", "");
        return d.length() > 10 ? d.substring(d.length() - 10) : d;
    }

    // ------------------------------------------------------------- own key pairs

    public void saveMyRsa(KeyPair kp, int bits) {
        keys.edit()
                .putInt("rsa_bits", bits)
                .putString("rsa_pub", CryptoCore.b64(kp.getPublic().getEncoded()))
                .putString("rsa_priv", CryptoCore.b64(kp.getPrivate().getEncoded()))
                .apply();
    }

    public void saveMyEc(KeyPair kp, CryptoCore.Curve curve) {
        keys.edit()
                .putString("ec_curve", curve.code)
                .putString("ec_pub", CryptoCore.b64(kp.getPublic().getEncoded()))
                .putString("ec_priv", CryptoCore.b64(kp.getPrivate().getEncoded()))
                .apply();
    }

    public boolean hasMyKeys() { return keys.contains("rsa_pub") && keys.contains("ec_pub"); }

    public int myRsaBits() { return keys.getInt("rsa_bits", 0); }

    public PublicKey myRsaPublic() throws GeneralSecurityException {
        return CryptoCore.rsaPublicFromB64(keys.getString("rsa_pub", ""));
    }

    public PrivateKey myRsaPrivate() throws GeneralSecurityException {
        return CryptoCore.rsaPrivateFromB64(keys.getString("rsa_priv", ""));
    }

    public CryptoCore.Curve myCurve() { return CryptoCore.Curve.fromCode(keys.getString("ec_curve", "256")); }

    public ECPublicKey myEcPublic() throws GeneralSecurityException {
        return CryptoCore.ecPublicFromB64(keys.getString("ec_pub", ""));
    }

    public PrivateKey myEcPrivate() throws GeneralSecurityException {
        return CryptoCore.ecPrivateFromB64(keys.getString("ec_priv", ""));
    }

    // ------------------------------------------------------------- contacts' public keys

    /**
     * Stores a key share received from {@code phone}. Returns a description, or null if the text is not a key.
     * Formats: K1:R:&lt;b64 X.509&gt;  or  K1:E:&lt;curve&gt;:&lt;b64 compressed point&gt;
     */
    public String importKeyShare(String phone, String text) throws GeneralSecurityException {
        String t = text.trim();
        if (!t.startsWith(CryptoCore.KEY_PREFIX)) return null;
        String[] parts = t.split(":");
        String who = normalize(phone);
        if (parts.length == 3 && parts[1].equals("R")) {
            PublicKey pk = CryptoCore.rsaPublicFromB64(parts[2]); // validates
            contacts.edit().putString("rsa:" + who, parts[2]).apply();
            return "RSA-" + (CryptoCore.rsaModulusBytes(pk) * 8) + " key, fingerprint "
                    + CryptoCore.fingerprint(pk.getEncoded());
        }
        if (parts.length == 4 && parts[1].equals("E")) {
            CryptoCore.Curve c = CryptoCore.Curve.fromCode(parts[2]);
            ECPublicKey pk = CryptoCore.decompress(c, CryptoCore.unb64(parts[3])); // validates point
            contacts.edit().putString("ec:" + who, parts[2] + ":" + parts[3]).apply();
            return c.label() + " key, fingerprint " + CryptoCore.fingerprint(pk.getEncoded());
        }
        throw new GeneralSecurityException("Malformed key share");
    }

    public PublicKey contactRsa(String phone) throws GeneralSecurityException {
        String b = contacts.getString("rsa:" + normalize(phone), null);
        return b == null ? null : CryptoCore.rsaPublicFromB64(b);
    }

    public CryptoCore.Curve contactCurve(String phone) {
        String v = contacts.getString("ec:" + normalize(phone), null);
        return v == null ? null : CryptoCore.Curve.fromCode(v.split(":")[0]);
    }

    public ECPublicKey contactEc(String phone) throws GeneralSecurityException {
        String v = contacts.getString("ec:" + normalize(phone), null);
        if (v == null) return null;
        String[] p = v.split(":");
        return CryptoCore.decompress(CryptoCore.Curve.fromCode(p[0]), CryptoCore.unb64(p[1]));
    }

    // ------------------------------------------------------------- inbox of encrypted SMS

    public static final class InboxItem {
        public String from;
        public String body;
        public long receivedAt;
    }

    public synchronized void addToInbox(String from, String body, long when) {
        try {
            JSONArray arr = new JSONArray(inbox.getString("items", "[]"));
            JSONObject o = new JSONObject();
            o.put("from", from);
            o.put("body", body);
            o.put("at", when);
            arr.put(o);
            inbox.edit().putString("items", arr.toString()).apply();
        } catch (JSONException ignored) {
        }
    }

    public synchronized List<InboxItem> loadInbox() {
        List<InboxItem> out = new ArrayList<>();
        try {
            JSONArray arr = new JSONArray(inbox.getString("items", "[]"));
            for (int i = arr.length() - 1; i >= 0; i--) { // newest first
                JSONObject o = arr.getJSONObject(i);
                InboxItem it = new InboxItem();
                it.from = o.getString("from");
                it.body = o.getString("body");
                it.receivedAt = o.getLong("at");
                out.add(it);
            }
        } catch (JSONException ignored) {
        }
        return out;
    }

    public synchronized void clearInbox() { inbox.edit().remove("items").apply(); }
}
