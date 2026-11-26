package mx.udlap.lis4062.securesms;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.text.format.DateFormat;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import mx.udlap.lis4062.securesms.crypto.Benchmark;
import mx.udlap.lis4062.securesms.crypto.CryptoCore;

/**
 * Receiver side: encrypted messages are kept encrypted and decrypted on demand with the private key.
 * For each received message the receiver can also run an RSA-vs-ECC comparison on the same plaintext.
 */
public class InboxActivity extends Activity {

    private KeyRepository repo;
    private ListView list;
    private View emptyView;
    private List<KeyRepository.InboxItem> items = new ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_inbox);
        if (getActionBar() != null) getActionBar().setDisplayHomeAsUpEnabled(true);
        repo = new KeyRepository(this);
        list = findViewById(R.id.lvInbox);
        emptyView = findViewById(R.id.emptyView);
        list.setOnItemClickListener((parent, view, pos, id) -> decrypt(items.get(pos)));
        findViewById(R.id.btnClear).setOnClickListener(v -> new AlertDialog.Builder(this)
                .setTitle("Clear inbox?")
                .setMessage("All stored encrypted messages will be deleted from this app.")
                .setPositiveButton("Clear", (d, w) -> {
                    repo.clearInbox();
                    reload();
                })
                .setNegativeButton("Cancel", null)
                .show());
    }

    @Override
    protected void onResume() {
        super.onResume();
        reload();
    }

    private void reload() {
        items = repo.loadInbox();
        list.setAdapter(new MessageAdapter(items));
        boolean empty = items.isEmpty();
        list.setVisibility(empty ? View.GONE : View.VISIBLE);
        emptyView.setVisibility(empty ? View.VISIBLE : View.GONE);
        findViewById(R.id.btnClear).setEnabled(!empty);
        setTitle(empty ? "Inbox" : "Inbox (" + items.size() + ")");
    }

    /** Chat-style row: colored algorithm badge, sender, time, ciphertext preview and SMS size. */
    private final class MessageAdapter extends ArrayAdapter<KeyRepository.InboxItem> {
        MessageAdapter(List<KeyRepository.InboxItem> data) {
            super(InboxActivity.this, 0, data);
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            View v = convertView != null ? convertView
                    : LayoutInflater.from(getContext()).inflate(R.layout.item_message, parent, false);
            KeyRepository.InboxItem it = getItem(position);
            boolean rsa = it.body.startsWith(CryptoCore.RSA_PREFIX);
            TextView badge = v.findViewById(R.id.tvBadge);
            badge.setText(rsa ? "RSA" : "ECC");
            badge.setBackgroundResource(rsa ? R.drawable.circle_rsa : R.drawable.circle_ecc);
            ((TextView) v.findViewById(R.id.tvFrom)).setText(it.from);
            ((TextView) v.findViewById(R.id.tvTime)).setText(DateFormat.format("dd MMM HH:mm", it.receivedAt));
            String payload = it.body.substring(it.body.lastIndexOf(':') + 1);
            ((TextView) v.findViewById(R.id.tvPreview)).setText("🔒 " + payload);
            int seg = CryptoCore.smsSegments(it.body.length());
            ((TextView) v.findViewById(R.id.tvMeta)).setText(it.body.length() + " chars · " + seg
                    + (seg == 1 ? " SMS" : " SMS parts") + " · tap to decrypt");
            return v;
        }
    }

    private void decrypt(KeyRepository.InboxItem it) {
        if (it == null) return;
        try {
            String plain, algo, meta;
            boolean rsa = it.body.startsWith(CryptoCore.RSA_PREFIX);
            long t0, t1;
            if (rsa) {
                byte[] ct = CryptoCore.unb64(it.body.substring(CryptoCore.RSA_PREFIX.length()));
                int k = CryptoCore.rsaModulusBytes(repo.myRsaPublic());
                t0 = System.nanoTime();
                byte[] pt = CryptoCore.rsaDecrypt(repo.myRsaPrivate(), k, ct);
                t1 = System.nanoTime();
                plain = new String(pt, StandardCharsets.UTF_8);
                algo = "RSA-" + k * 8 + " OAEP";
                meta = (ct.length / k) + " RSA block(s) of " + k + " bytes · " + it.body.length() + " SMS chars";
            } else {
                String[] p = it.body.split(":", 3); // E1 : curve : base64
                CryptoCore.Curve c = CryptoCore.Curve.fromCode(p[1]);
                if (c != repo.myCurve()) throw new IllegalStateException("Message uses P-" + c.code
                        + " but your key is P-" + repo.myCurve().code);
                byte[] data = CryptoCore.unb64(p[2]);
                t0 = System.nanoTime();
                byte[] pt = CryptoCore.eciesDecrypt(c, repo.myEcPrivate(), data);
                t1 = System.nanoTime();
                plain = new String(pt, StandardCharsets.UTF_8);
                algo = "ECIES P-" + c.code;
                meta = "AES-128-GCM tag verified: the message was not modified · " + it.body.length() + " SMS chars";
            }
            View v = LayoutInflater.from(this).inflate(R.layout.dialog_decrypted, null);
            ((TextView) v.findViewById(R.id.tvDFrom)).setText("From " + it.from + " · "
                    + DateFormat.format("dd MMM yyyy, HH:mm", it.receivedAt));
            ((TextView) v.findViewById(R.id.tvDPlain)).setText(plain);
            TextView chipAlgo = v.findViewById(R.id.tvDAlgo);
            chipAlgo.setText(algo);
            chipAlgo.setBackgroundResource(rsa ? R.drawable.chip_rsa : R.drawable.chip_ecc);
            chipAlgo.setTextColor(getColor(rsa ? R.color.rsa : R.color.ecc));
            ((TextView) v.findViewById(R.id.tvDTime)).setText(String.format(Locale.US, "Decrypted in %.2f ms",
                    (t1 - t0) / 1e6));
            ((TextView) v.findViewById(R.id.tvDMeta)).setText(meta);
            final String plaintext = plain;
            new AlertDialog.Builder(this)
                    .setView(v)
                    .setPositiveButton("Close", null)
                    .setNeutralButton("Compare RSA vs ECC", (d, w) -> compare(plaintext))
                    .show();
        } catch (Exception e) {
            new AlertDialog.Builder(this)
                    .setTitle("Cannot decrypt")
                    .setMessage(e.getClass().getSimpleName() + ": " + e.getMessage()
                            + "\n\nWrong key (keys regenerated?) or the message was modified in transit.")
                    .setPositiveButton("OK", null)
                    .show();
        }
    }

    /** Encrypt/decrypt the received plaintext with the receiver's RSA key AND its ECC key, 30 times each. */
    private void compare(String plaintext) {
        Toast.makeText(this, "Measuring RSA and ECC on this message…", Toast.LENGTH_SHORT).show();
        final int len = plaintext.length();
        new Thread(() -> {
            try {
                List<Benchmark.Result> rs = new ArrayList<>();
                rs.add(Benchmark.runRsa(repo.myRsaBits(), len, 1, 5, 30, null));
                rs.add(Benchmark.runEcc(repo.myCurve(), len, 1, 5, 30, null));
                runOnUiThread(() -> {
                    LinearLayout box = new LinearLayout(this);
                    box.setOrientation(LinearLayout.VERTICAL);
                    int p = ResultsTable.dp(this, 20);
                    box.setPadding(p, p / 2, p, 0);
                    TextView note = new TextView(this);
                    note.setText(len + "-character message, 30 runs each, measured on this phone (receiver).");
                    note.setTextColor(getColor(R.color.text2));
                    note.setTextSize(12);
                    note.setPadding(0, 0, 0, ResultsTable.dp(this, 8));
                    box.addView(note);
                    box.addView(ResultsTable.build(this, rs));
                    new AlertDialog.Builder(this)
                            .setTitle("RSA vs ECC at the receiver")
                            .setView(box)
                            .setPositiveButton("OK", null)
                            .show();
                });
            } catch (Exception ex) {
                runOnUiThread(() -> Toast.makeText(this, "Error: " + ex.getMessage(), Toast.LENGTH_LONG).show());
            }
        }).start();
    }
}
