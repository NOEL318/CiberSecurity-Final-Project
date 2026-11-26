package mx.udlap.lis4062.securesms;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import mx.udlap.lis4062.securesms.crypto.CryptoCore;

/**
 * Sender side: key generation, public-key exchange over SMS, encryption and sending.
 */
public class MainActivity extends Activity {

    private static final int REQ_SMS = 1;
    private static final Integer[] RSA_SIZES = {512, 1024, 2048, 3072, 4096};

    private KeyRepository repo;
    private Spinner spRsaBits, spCurve;
    private TextView tvMyKeys, tvContact, tvCipher, tvCounter, tvEstimate, tvAlgoHint;
    private TextView tvChipKeys, tvChipInbox, tvChipRsa, tvChipEcc, tvInboxCount;
    private TextView tvCipherAlgo, tvCipherSize, tvCipherTime, tvCipherInfo;
    private View cardCipher;
    private ProgressBar pbKeys;
    private Button btnGenerate;
    private EditText etPhone, etMessage;
    private RadioButton rbRsa;
    private final List<CryptoCore.Curve> curves = new ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        repo = new KeyRepository(this);

        spRsaBits = findViewById(R.id.spRsaBits);
        spCurve = findViewById(R.id.spCurve);
        tvMyKeys = findViewById(R.id.tvMyKeys);
        tvContact = findViewById(R.id.tvContact);
        tvCipher = findViewById(R.id.tvCipher);
        tvCounter = findViewById(R.id.tvCounter);
        tvEstimate = findViewById(R.id.tvEstimate);
        tvAlgoHint = findViewById(R.id.tvAlgoHint);
        tvChipKeys = findViewById(R.id.tvChipKeys);
        tvChipInbox = findViewById(R.id.tvChipInbox);
        tvChipRsa = findViewById(R.id.tvChipRsa);
        tvChipEcc = findViewById(R.id.tvChipEcc);
        tvInboxCount = findViewById(R.id.tvInboxCount);
        tvCipherAlgo = findViewById(R.id.tvCipherAlgo);
        tvCipherSize = findViewById(R.id.tvCipherSize);
        tvCipherTime = findViewById(R.id.tvCipherTime);
        tvCipherInfo = findViewById(R.id.tvCipherInfo);
        cardCipher = findViewById(R.id.cardCipher);
        pbKeys = findViewById(R.id.pbKeys);
        btnGenerate = findViewById(R.id.btnGenerate);
        etPhone = findViewById(R.id.etPhone);
        etMessage = findViewById(R.id.etMessage);
        rbRsa = findViewById(R.id.rbRsa);

        List<String> rsaLabels = new ArrayList<>();
        for (Integer b : RSA_SIZES) rsaLabels.add(b + (b == 512 ? "  (insecure)" : ""));
        spRsaBits.setAdapter(adapter(rsaLabels));
        spRsaBits.setSelection(2); // 2048 (112-bit security, NIST minimum)

        List<String> curveLabels = new ArrayList<>();
        for (CryptoCore.Curve c : CryptoCore.Curve.values()) {
            if (CryptoCore.isCurveSupported(c)) {
                curves.add(c);
                curveLabels.add("P-" + c.code);
            }
        }
        spCurve.setAdapter(adapter(curveLabels));
        int p256 = curves.indexOf(CryptoCore.Curve.P256);
        if (p256 >= 0) spCurve.setSelection(p256);

        btnGenerate.setOnClickListener(v -> generateKeys());
        findViewById(R.id.btnSendKeys).setOnClickListener(v -> sendMyKeys());
        findViewById(R.id.btnPasteKey).setOnClickListener(v -> pasteContactKey());
        findViewById(R.id.btnPreview).setOnClickListener(v -> encrypt(false));
        findViewById(R.id.btnSend).setOnClickListener(v -> encrypt(true));
        findViewById(R.id.btnCopy).setOnClickListener(v -> copyCiphertext());
        findViewById(R.id.tileInbox).setOnClickListener(
                v -> startActivity(new Intent(this, InboxActivity.class)));
        findViewById(R.id.tileBench).setOnClickListener(
                v -> startActivity(new Intent(this, BenchmarkActivity.class)));

        ((RadioGroup) findViewById(R.id.rgAlgo)).setOnCheckedChangeListener((g, id) -> {
            tvAlgoHint.setText(rbRsa.isChecked()
                    ? "RSA with OAEP padding, message split into fixed-size blocks."
                    : "ECIES: ephemeral ECDH + AES-128-GCM. Smaller SMS and tamper detection.");
            updateEstimate();
        });

        etPhone.addTextChangedListener(new SimpleWatcher(() -> {
            refreshContact();
            updateEstimate();
        }));
        etMessage.addTextChangedListener(new SimpleWatcher(this::updateEstimate));

        requestSmsPermissions();
        refreshMyKeys();
        refreshContact();
        updateEstimate();
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshContact(); // a key may have arrived by SMS meanwhile
        int n = repo.loadInbox().size();
        tvChipInbox.setText("✉ " + n);
        tvInboxCount.setText(n == 0 ? "No encrypted SMS yet" : n + " encrypted SMS");
    }

    private ArrayAdapter<String> adapter(List<String> items) {
        ArrayAdapter<String> a = new ArrayAdapter<>(this, R.layout.spinner_item, items);
        a.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        return a;
    }

    // ------------------------------------------------------------------ permissions

    private void requestSmsPermissions() {
        if (checkSelfPermission(Manifest.permission.SEND_SMS) != PackageManager.PERMISSION_GRANTED
                || checkSelfPermission(Manifest.permission.RECEIVE_SMS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.SEND_SMS, Manifest.permission.RECEIVE_SMS}, REQ_SMS);
        }
    }

    private boolean canSend() {
        if (checkSelfPermission(Manifest.permission.SEND_SMS) == PackageManager.PERMISSION_GRANTED) return true;
        requestSmsPermissions();
        toast("SMS permission is required");
        return false;
    }

    // ------------------------------------------------------------------ keys

    private void generateKeys() {
        final int bits = RSA_SIZES[spRsaBits.getSelectedItemPosition()];
        final CryptoCore.Curve curve = curves.get(spCurve.getSelectedItemPosition());
        if (repo.hasMyKeys()) {
            new AlertDialog.Builder(this)
                    .setTitle("Replace key pairs?")
                    .setMessage("Messages encrypted with your old public keys can no longer be decrypted, and "
                            + "your contacts must receive your new public keys.")
                    .setPositiveButton("Replace", (d, w) -> doGenerate(bits, curve))
                    .setNegativeButton("Cancel", null)
                    .show();
        } else {
            doGenerate(bits, curve);
        }
    }

    private void doGenerate(int bits, CryptoCore.Curve curve) {
        btnGenerate.setEnabled(false);
        pbKeys.setVisibility(View.VISIBLE);
        tvMyKeys.setText("Generating RSA-" + bits + " and P-" + curve.code + " …");
        new Thread(() -> {
            try {
                long t0 = System.nanoTime();
                KeyPair rsa = CryptoCore.generateRsa(bits);
                long t1 = System.nanoTime();
                KeyPair ec = CryptoCore.generateEc(curve);
                long t2 = System.nanoTime();
                repo.saveMyRsa(rsa, bits);
                repo.saveMyEc(ec, curve);
                final String timing = String.format(Locale.US,
                        "\n\nKey generation\n  RSA-%d  %.1f ms\n  P-%s  %.2f ms", bits, (t1 - t0) / 1e6,
                        curve.code, (t2 - t1) / 1e6);
                runOnUiThread(() -> {
                    refreshMyKeys();
                    tvMyKeys.append(timing);
                    updateEstimate();
                });
            } catch (Exception e) {
                runOnUiThread(() -> tvMyKeys.setText("Error: " + e));
            } finally {
                runOnUiThread(() -> {
                    btnGenerate.setEnabled(true);
                    pbKeys.setVisibility(View.GONE);
                });
            }
        }).start();
    }

    private void refreshMyKeys() {
        if (!repo.hasMyKeys()) {
            tvMyKeys.setText("No keys yet. Choose the sizes and press Generate.");
            tvChipKeys.setText("● No keys yet");
            return;
        }
        try {
            PublicKey rsa = repo.myRsaPublic();
            ECPublicKey ec = repo.myEcPublic();
            tvMyKeys.setText(String.format(Locale.US,
                    "RSA-%d · public key %d B\n  fp %s\nP-%s · public key %d B\n  fp %s",
                    repo.myRsaBits(), rsa.getEncoded().length, CryptoCore.fingerprint(rsa.getEncoded()),
                    repo.myCurve().code, CryptoCore.compress(ec).length, CryptoCore.fingerprint(ec.getEncoded())));
            tvChipKeys.setText("● RSA-" + repo.myRsaBits() + " · P-" + repo.myCurve().code + " ready");
        } catch (Exception e) {
            tvMyKeys.setText("Stored keys unreadable: " + e);
        }
    }

    private void sendMyKeys() {
        String phone = etPhone.getText().toString().trim();
        if (phone.isEmpty()) { toast("Enter the contact's number"); return; }
        if (!repo.hasMyKeys()) { toast("Generate your keys first"); return; }
        if (!canSend()) return;
        try {
            String rsaShare = CryptoCore.rsaKeyShare(repo.myRsaPublic());
            String ecShare = CryptoCore.eccKeyShare(repo.myCurve(), repo.myEcPublic());
            int s1 = SmsSender.send(this, phone, rsaShare);
            int s2 = SmsSender.send(this, phone, ecShare);
            showCipher("Public keys", R.drawable.chip_primary, R.color.primary,
                    (s1 + s2) + " SMS", "sent",
                    "Ask your contact to compare these fingerprints by voice to rule out a man-in-the-middle.",
                    rsaShare + "\n\n" + ecShare);
            toast("Public keys sent to " + phone);
        } catch (Exception e) {
            toast("Error: " + e.getMessage());
        }
    }

    /** Manual key import (useful when testing on one device or when SMS key exchange is not possible). */
    private void pasteContactKey() {
        String phone = etPhone.getText().toString().trim();
        if (phone.isEmpty()) { toast("Enter the contact's number first"); return; }
        final EditText input = new EditText(this);
        input.setHint("K1:R:… or K1:E:256:…");
        ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        if (cm != null && cm.hasPrimaryClip() && cm.getPrimaryClip().getItemCount() > 0) {
            CharSequence clip = cm.getPrimaryClip().getItemAt(0).getText();
            if (clip != null && clip.toString().startsWith(CryptoCore.KEY_PREFIX)) input.setText(clip);
        }
        new AlertDialog.Builder(this)
                .setTitle("Paste public key of " + phone)
                .setView(input)
                .setPositiveButton("Import", (d, w) -> {
                    try {
                        String desc = repo.importKeyShare(phone, input.getText().toString());
                        toast(desc == null ? "Not a key share (must start with K1:)" : "Imported " + desc);
                        refreshContact();
                        updateEstimate();
                    } catch (Exception e) {
                        toast("Invalid key: " + e.getMessage());
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void refreshContact() {
        String phone = etPhone.getText().toString().trim();
        if (phone.isEmpty()) {
            setChip(tvChipRsa, "RSA key —", false, true);
            setChip(tvChipEcc, "ECC key —", false, false);
            tvContact.setText("Enter a phone number to see its public keys.");
            return;
        }
        try {
            PublicKey rsa = repo.contactRsa(phone);
            CryptoCore.Curve c = repo.contactCurve(phone);
            ECPublicKey ec = repo.contactEc(phone);
            setChip(tvChipRsa, rsa == null ? "RSA key missing" : "✓ RSA-" + CryptoCore.rsaModulusBytes(rsa) * 8,
                    rsa != null, true);
            setChip(tvChipEcc, ec == null ? "ECC key missing" : "✓ ECC P-" + c.code, ec != null, false);
            if (rsa == null && ec == null) {
                tvContact.setText("No keys for " + KeyRepository.normalize(phone)
                        + " yet. Ask them to send their keys, or paste them.");
            } else {
                tvContact.setText("Fingerprints  "
                        + (rsa == null ? "" : "RSA " + CryptoCore.fingerprint(rsa.getEncoded()))
                        + (rsa != null && ec != null ? "   " : "")
                        + (ec == null ? "" : "ECC " + CryptoCore.fingerprint(ec.getEncoded())));
            }
        } catch (Exception e) {
            tvContact.setText("Error reading contact keys: " + e.getMessage());
        }
    }

    private void setChip(TextView chip, String text, boolean ok, boolean isRsa) {
        chip.setText(text);
        if (ok) {
            chip.setBackgroundResource(isRsa ? R.drawable.chip_rsa : R.drawable.chip_ecc);
            chip.setTextColor(getColor(isRsa ? R.color.rsa : R.color.ecc));
        } else {
            chip.setBackgroundResource(R.drawable.chip_muted);
            chip.setTextColor(getColor(R.color.text2));
        }
    }

    // ------------------------------------------------------------------ live SMS size estimate

    private void updateEstimate() {
        String msg = etMessage.getText().toString();
        int bytes = msg.getBytes(StandardCharsets.UTF_8).length;
        tvCounter.setText(msg.length() + " ch");
        if (msg.isEmpty()) {
            tvEstimate.setText("SMS estimate appears as you type");
            return;
        }
        String phone = etPhone.getText().toString().trim();
        int k = 256;
        CryptoCore.Curve curve = CryptoCore.Curve.P256;
        try {
            PublicKey cr = phone.isEmpty() ? null : repo.contactRsa(phone);
            if (cr != null) k = CryptoCore.rsaModulusBytes(cr);
            else if (repo.myRsaBits() > 0) k = repo.myRsaBits() / 8;
            CryptoCore.Curve cc = phone.isEmpty() ? null : repo.contactCurve(phone);
            if (cc != null) curve = cc;
            else if (repo.hasMyKeys()) curve = repo.myCurve();
        } catch (Exception ignored) {
        }
        int blocks = Math.max(1, (bytes + (k - 42) - 1) / (k - 42));
        int rsaChars = CryptoCore.RSA_PREFIX.length() + 4 * ((blocks * k + 2) / 3);
        int point = (Integer.parseInt(curve.code) + 7) / 8 + 1;
        int eccChars = (CryptoCore.ECC_PREFIX + curve.code + ":").length() + 4 * ((point + bytes + 16 + 2) / 3);
        tvEstimate.setText(String.format(Locale.US, "RSA-%d → %d SMS  ·  P-%s → %d SMS",
                k * 8, CryptoCore.smsSegments(rsaChars), curve.code, CryptoCore.smsSegments(eccChars)));
    }

    // ------------------------------------------------------------------ encryption

    private void encrypt(boolean send) {
        String phone = etPhone.getText().toString().trim();
        String msg = etMessage.getText().toString();
        if (phone.isEmpty() || msg.isEmpty()) { toast("Phone number and message are required"); return; }
        if (send && !canSend()) return;
        try {
            String wire;
            String algo;
            boolean isRsa = rbRsa.isChecked();
            long t0 = System.nanoTime();
            if (isRsa) {
                PublicKey pk = repo.contactRsa(phone);
                if (pk == null) { toast("No RSA public key for this contact yet"); return; }
                wire = CryptoCore.wrapRsa(pk, msg);
                algo = "RSA-" + CryptoCore.rsaModulusBytes(pk) * 8;
            } else {
                ECPublicKey pk = repo.contactEc(phone);
                CryptoCore.Curve c = repo.contactCurve(phone);
                if (pk == null) { toast("No ECC public key for this contact yet"); return; }
                wire = CryptoCore.wrapEcc(c, pk, msg);
                algo = "ECIES P-" + c.code;
            }
            double ms = (System.nanoTime() - t0) / 1e6;
            int segments = CryptoCore.smsSegments(wire.length());
            String info = String.format(Locale.US, "%d plaintext chars → %d ciphertext chars (Base64).%s",
                    msg.length(), wire.length(),
                    send ? " Sent to " + phone + "." : " Preview only — not sent.");
            if (send) {
                SmsSender.send(this, phone, wire);
                etMessage.setText("");
                toast("Encrypted SMS sent");
            }
            showCipher(algo, isRsa ? R.drawable.chip_rsa : R.drawable.chip_ecc, isRsa ? R.color.rsa : R.color.ecc,
                    segments + (segments == 1 ? " SMS" : " SMS parts"), String.format(Locale.US, "%.2f ms", ms),
                    info, wire);
        } catch (Exception e) {
            toast("Encryption error: " + e.getMessage());
        }
    }

    private void showCipher(String algo, int chipBg, int chipColor, String size, String time, String info,
                            String text) {
        cardCipher.setVisibility(View.VISIBLE);
        tvCipherAlgo.setText(algo);
        tvCipherAlgo.setBackgroundResource(chipBg);
        tvCipherAlgo.setTextColor(getColor(chipColor));
        tvCipherSize.setText(size);
        tvCipherTime.setText(time);
        tvCipherInfo.setText(info);
        tvCipher.setText(text);
    }

    private void copyCiphertext() {
        ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        if (cm != null) {
            cm.setPrimaryClip(ClipData.newPlainText("ciphertext", tvCipher.getText()));
            toast("Copied");
        }
    }

    private void toast(String s) { Toast.makeText(this, s, Toast.LENGTH_LONG).show(); }

    /** Minimal TextWatcher adapter. */
    static final class SimpleWatcher implements TextWatcher {
        private final Runnable r;
        SimpleWatcher(Runnable r) { this.r = r; }
        @Override public void beforeTextChanged(CharSequence s, int a, int b, int c) { }
        @Override public void onTextChanged(CharSequence s, int a, int b, int c) { }
        @Override public void afterTextChanged(Editable s) { r.run(); }
    }
}
