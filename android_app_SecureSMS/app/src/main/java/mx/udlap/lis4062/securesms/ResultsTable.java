package mx.udlap.lis4062.securesms;

import android.content.Context;
import android.graphics.Typeface;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import mx.udlap.lis4062.securesms.crypto.Benchmark;

/**
 * Builds a compact results table: one row per scheme with key-generation, encryption and decryption time,
 * SMS segments, and a bar proportional to the decryption time (the receiver's cost).
 * Results with different message lengths are grouped under a sub-header.
 */
final class ResultsTable {

    private static final float[] W = {2.15f, 0.9f, 1.1f, 1f, 1f, 0.8f};

    private ResultsTable() { }

    static View build(Context c, List<Benchmark.Result> results) {
        LinearLayout root = new LinearLayout(c);
        root.setOrientation(LinearLayout.VERTICAL);

        Map<Integer, List<Benchmark.Result>> groups = new LinkedHashMap<>();
        for (Benchmark.Result r : results) {
            List<Benchmark.Result> g = groups.get(r.messageChars);
            if (g == null) {
                g = new ArrayList<>();
                groups.put(r.messageChars, g);
            }
            g.add(r);
        }

        root.addView(row(c, new String[]{"Scheme", "Sec.", "KeyGen", "Enc", "Dec", "SMS"}, true, null));
        TextView units = text(c, "times in milliseconds · security in bits", 11, R.color.text3, false);
        units.setPadding(0, 0, 0, dp(c, 6));
        root.addView(units);

        for (Map.Entry<Integer, List<Benchmark.Result>> e : groups.entrySet()) {
            if (groups.size() > 1) {
                TextView sub = text(c, e.getKey() + "-character message", 12, R.color.primary, true);
                sub.setPadding(0, dp(c, 10), 0, dp(c, 2));
                root.addView(sub);
            }
            double maxDec = 0, minDec = Double.MAX_VALUE;
            for (Benchmark.Result r : e.getValue()) {
                maxDec = Math.max(maxDec, r.decMs);
                minDec = Math.min(minDec, r.decMs);
            }
            for (Benchmark.Result r : e.getValue()) {
                boolean ecc = "ECC".equals(r.family);
                String[] cells = {r.scheme.replace("ECC ", ""), r.securityBits.replace(" (broken)", "!"),
                        fmt(r.keyGenMs), fmt(r.encMs), fmt(r.decMs), String.valueOf(r.smsSegments)};
                LinearLayout line = row(c, cells, false, ecc ? R.drawable.circle_ecc : R.drawable.circle_rsa);
                if (r.decMs == minDec && e.getValue().size() > 1) {
                    TextView dec = (TextView) line.getChildAt(4);
                    dec.setTextColor(c.getColor(R.color.ok));
                    dec.setTypeface(Typeface.DEFAULT_BOLD);
                }
                root.addView(line);
                root.addView(bar(c, maxDec > 0 ? r.decMs / maxDec : 0, ecc));
            }
        }
        return root;
    }

    private static LinearLayout row(Context c, String[] cells, boolean header, Integer dot) {
        LinearLayout row = new LinearLayout(c);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(0, dp(c, header ? 2 : 8), 0, dp(c, 2));
        for (int i = 0; i < cells.length; i++) {
            TextView t = text(c, cells[i], header ? 11 : 13, header ? R.color.text2 : R.color.text,
                    header || i == 0);
            t.setGravity(i == 0 ? Gravity.START | Gravity.CENTER_VERTICAL : Gravity.END | Gravity.CENTER_VERTICAL);
            if (i == 0 && dot != null) {
                t.setCompoundDrawablesRelativeWithIntrinsicBounds(scaledDot(c, dot), null, null, null);
                t.setCompoundDrawablePadding(dp(c, 6));
            }
            t.setLayoutParams(new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, W[i]));
            row.addView(t);
        }
        return row;
    }

    private static android.graphics.drawable.Drawable scaledDot(Context c, int res) {
        return new SizedDrawable(c.getDrawable(res), dp(c, 8));
    }

    /** Wraps a drawable so that it reports a fixed intrinsic size. */
    private static final class SizedDrawable extends android.graphics.drawable.LayerDrawable {
        private final int size;
        SizedDrawable(android.graphics.drawable.Drawable d, int size) {
            super(new android.graphics.drawable.Drawable[]{d});
            this.size = size;
        }
        @Override public int getIntrinsicWidth() { return size; }
        @Override public int getIntrinsicHeight() { return size; }
    }

    private static View bar(Context c, double fraction, boolean ecc) {
        LinearLayout track = new LinearLayout(c);
        track.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(c, 6));
        lp.setMargins(dp(c, 14), dp(c, 2), 0, dp(c, 4));
        track.setLayoutParams(lp);
        float f = (float) Math.max(0.02, Math.min(1.0, fraction));
        View fill = new View(c);
        fill.setBackgroundResource(ecc ? R.drawable.bar_ecc : R.drawable.bar_rsa);
        fill.setLayoutParams(new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.MATCH_PARENT, f));
        View rest = new View(c);
        rest.setLayoutParams(new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.MATCH_PARENT, 1f - f + 0.0001f));
        track.addView(fill);
        track.addView(rest);
        return track;
    }

    private static TextView text(Context c, String s, int sp, int color, boolean bold) {
        TextView t = new TextView(c);
        t.setText(s);
        t.setTextSize(sp);
        t.setTextColor(c.getColor(color));
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        t.setMaxLines(1);
        return t;
    }

    static String fmt(double ms) {
        if (ms >= 100) return String.format(Locale.US, "%.0f", ms);
        if (ms >= 10) return String.format(Locale.US, "%.1f", ms);
        if (ms >= 1) return String.format(Locale.US, "%.2f", ms);
        return String.format(Locale.US, "%.3f", ms);
    }

    static int dp(Context c, int v) {
        return Math.round(v * c.getResources().getDisplayMetrics().density);
    }
}
