import mx.udlap.lis4062.securesms.crypto.Benchmark;
import mx.udlap.lis4062.securesms.crypto.CryptoCore;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

/** Desktop run of the exact same crypto/benchmark code used inside the Android app. */
public class BenchmarkMain {
    public static void main(String[] args) throws Exception {
        String outDir = args.length > 0 ? args[0] : ".";
        Benchmark.Progress p = System.out::println;
        System.out.println("Java " + System.getProperty("java.version") + " / " + System.getProperty("os.arch")
                + " / cores=" + Runtime.getRuntime().availableProcessors());

        // 0) JIT warm-up pass (results discarded)
        Benchmark.runSuite(new int[]{512, 1024, 2048, 3072}, 140, 3, 50, 200, null);
        if (args.length > 1 && args[1].equals("keysonly")) {
            List<Benchmark.Result> m = Benchmark.runSuite(new int[]{512, 1024, 2048, 3072, 4096, 7680}, 140, 15, 30, 300, p);
            try (PrintWriter w = new PrintWriter(outDir + "/bench_keysizes.csv")) {
                w.println(Benchmark.Result.csvHeader());
                for (Benchmark.Result r : m) w.println(r.toCsv());
            }
            return;
        }
        if (args.length > 1 && args[1].equals("sweeponly")) {
            for (int len : new int[]{16, 1024}) { // extra warm-up of every scheme/length path
                Benchmark.runRsa(2048, len, 1, 50, 100, null); Benchmark.runRsa(3072, len, 1, 50, 100, null);
                Benchmark.runEcc(CryptoCore.Curve.P256, len, 1, 50, 100, null);
                Benchmark.runEcc(CryptoCore.Curve.P384, len, 1, 50, 100, null);
            }
            List<Benchmark.Result> sw = new ArrayList<>();
            for (int len : new int[]{16, 64, 140, 256, 512, 1024}) {
                sw.add(Benchmark.runRsa(2048, len, 3, 30, 300, p));
                sw.add(Benchmark.runRsa(3072, len, 3, 30, 300, p));
                sw.add(Benchmark.runEcc(CryptoCore.Curve.P256, len, 3, 30, 300, p));
                sw.add(Benchmark.runEcc(CryptoCore.Curve.P384, len, 3, 30, 300, p));
            }
            try (PrintWriter w = new PrintWriter(outDir + "/bench_msglen.csv")) {
                w.println(Benchmark.Result.csvHeader());
                for (Benchmark.Result r : sw) w.println(r.toCsv());
            }
            return;
        }
        // 1) Key-size comparison at a typical SMS length (140 characters)
        int[] rsaBits = {512, 1024, 2048, 3072, 4096, 7680};
        List<Benchmark.Result> main = Benchmark.runSuite(rsaBits, 140, 12, 30, 300, p);
        try (PrintWriter w = new PrintWriter(outDir + "/bench_keysizes.csv")) {
            w.println(Benchmark.Result.csvHeader());
            for (Benchmark.Result r : main) w.println(r.toCsv());
        }

        // 2) Message-length sweep at equivalent security levels (112/128/192 bits)
        int[] lengths = {16, 64, 140, 256, 512, 1024};
        List<Benchmark.Result> sweep = new ArrayList<>();
        for (int len : lengths) {
            sweep.add(Benchmark.runRsa(2048, len, 1, 20, 200, p));
            sweep.add(Benchmark.runRsa(3072, len, 1, 20, 200, p));
            sweep.add(Benchmark.runEcc(CryptoCore.Curve.P256, len, 1, 20, 200, p));
            sweep.add(Benchmark.runEcc(CryptoCore.Curve.P384, len, 1, 20, 200, p));
        }
        try (PrintWriter w = new PrintWriter(outDir + "/bench_msglen.csv")) {
            w.println(Benchmark.Result.csvHeader());
            for (Benchmark.Result r : sweep) w.println(r.toCsv());
        }
        System.out.println("done");
    }
}
