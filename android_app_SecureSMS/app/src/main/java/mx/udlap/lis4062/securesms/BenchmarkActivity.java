package mx.udlap.lis4062.securesms;

import android.app.Activity;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;

import mx.udlap.lis4062.securesms.crypto.Benchmark;
import mx.udlap.lis4062.securesms.crypto.CryptoCore;

/**
 * RSA vs ECC comparison executed on the receiver device:
 *  - key-size test: RSA 512..4096 and every ECC curve the platform supports, same message
 *  - length sweep : RSA-2048 / RSA-3072 / P-256 / P-384 for 16..1024 characters
 * Results are shown as a table with bars and can be shared as CSV for the report.
 */
public class BenchmarkActivity extends Activity {

    private TextView tvLog, tvStatus;
    private LinearLayout llResults;
    private View rowProgress;
    private EditText etLen, etIters;
    private Button btnKeys, btnSweep, btnShare, btnToggleLog;
    private final List<Benchmark.Result> results = new ArrayList<>();
    private volatile boolean running;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_benchmark);
        if (getActionBar() != null) getActionBar().setDisplayHomeAsUpEnabled(true);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        tvLog = findViewById(R.id.tvLog);
        tvStatus = findViewById(R.id.tvStatus);
        llResults = findViewById(R.id.llResults);
        rowProgress = findViewById(R.id.rowProgress);
        etLen = findViewById(R.id.etLen);
        etIters = findViewById(R.id.etIters);
        btnKeys = findViewById(R.id.btnRunKeys);
        btnSweep = findViewById(R.id.btnRunSweep);
        btnShare = findViewById(R.id.btnShare);
        btnToggleLog = findViewById(R.id.btnToggleLog);
        ((TextView) findViewById(R.id.tvDevice)).setText(deviceInfo()
                + "\nKeep the screen on and the phone plugged in for stable timings.");
        btnKeys.setOnClickListener(v -> start(false));
        btnSweep.setOnClickListener(v -> start(true));
        btnShare.setOnClickListener(v -> share());
        btnShare.setEnabled(false);
        btnToggleLog.setOnClickListener(v -> {
            boolean show = tvLog.getVisibility() != View.VISIBLE;
            tvLog.setVisibility(show ? View.VISIBLE : View.GONE);
            btnToggleLog.setText(show ? "Hide" : "Show");
        });
    }

    private static String deviceInfo() {
        return Build.MANUFACTURER + " " + Build.MODEL + " · Android " + Build.VERSION.RELEASE
                + " (API " + Build.VERSION.SDK_INT + ") · " + Runtime.getRuntime().availableProcessors() + " cores";
    }

    private void log(String s) {
        runOnUiThread(() -> {
            tvLog.append("\n" + s);
            tvStatus.setText(s.trim());
        });
    }

    private void start(boolean sweep) {
        if (running) return;
        final int len = parse(etLen, 140);
        final int iters = parse(etIters, 50);
        running = true;
        results.clear();
        setBusy(true);
        tvLog.setText(deviceInfo());
        new Thread(() -> {
            try {
                if (!sweep) {
                    log("Key-size test, message = " + len + " chars, " + iters + " iterations");
                    results.addAll(Benchmark.runSuite(new int[]{512, 1024, 2048, 3072, 4096}, len, 5, 5, iters,
                            this::log));
                } else {
                    log("Length sweep, " + iters + " iterations");
                    for (int l : new int[]{16, 64, 140, 256, 512, 1024}) {
                        results.add(Benchmark.runRsa(2048, l, 1, 5, iters, this::log));
                        results.add(Benchmark.runRsa(3072, l, 1, 5, iters, this::log));
                        results.add(Benchmark.runEcc(CryptoCore.Curve.P256, l, 1, 5, iters, this::log));
                        results.add(Benchmark.runEcc(CryptoCore.Curve.P384, l, 1, 5, iters, this::log));
                    }
                }
                log("\nCSV:\n" + csv());
                runOnUiThread(() -> {
                    llResults.removeAllViews();
                    llResults.addView(ResultsTable.build(this, results));
                });
            } catch (Exception e) {
                log("ERROR: " + e);
            } finally {
                running = false;
                runOnUiThread(() -> {
                    setBusy(false);
                    tvStatus.setText("Done · " + results.size() + " configurations");
                });
            }
        }).start();
    }

    private void setBusy(boolean busy) {
        btnKeys.setEnabled(!busy);
        btnSweep.setEnabled(!busy);
        btnShare.setEnabled(!busy && !results.isEmpty());
        rowProgress.setVisibility(View.VISIBLE);
        findViewById(R.id.pbBench).setVisibility(busy ? View.VISIBLE : View.GONE);
    }

    private String csv() {
        StringBuilder sb = new StringBuilder(Benchmark.Result.csvHeader()).append('\n');
        for (Benchmark.Result r : results) sb.append(r.toCsv()).append('\n');
        return sb.toString();
    }

    private void share() {
        if (results.isEmpty()) return;
        Intent i = new Intent(Intent.ACTION_SEND);
        i.setType("text/plain");
        i.putExtra(Intent.EXTRA_SUBJECT, "RSA vs ECC benchmark - " + Build.MODEL);
        i.putExtra(Intent.EXTRA_TEXT, deviceInfo() + "\n" + csv());
        startActivity(Intent.createChooser(i, "Share results"));
    }

    private static int parse(EditText e, int def) {
        try {
            int v = Integer.parseInt(e.getText().toString().trim());
            return v > 0 ? v : def;
        } catch (NumberFormatException ex) {
            return def;
        }
    }
}
