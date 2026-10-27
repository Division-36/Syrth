/*
 * SYRTH v2 C engine benchmark harness.
 *
 * Compile against the generated syrth_engine.h (see
 *   python -m syrth.classifier.export --model model.joblib --output syrth_engine.h)
 *
 *   cc -O2 -o test_c_engine test_c_engine.c
 *   ./test_c_engine <num_iterations>
 *
 * Measures per-call prediction latency of the pure-C tree engine.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include "../syrth_engine.h"

/* Prevent function inlining for consistent measurements */
static int __attribute__((noinline)) benchmark_iteration(
    const float* features, int num_features, float* conf
) {
    return syrth_predict(features, num_features, conf);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <num_iterations>\n", argv[0]);
        return 1;
    }

    int n = atoi(argv[1]);
    if (n < 1) n = 100;

    /* A few deterministic 53-dim feature vectors (SQLi / RCE / XSS / safe) */
    static float vec1[SYRTH_NUM_FEATURES]; /* zeros: no signals */
    static float vec2[SYRTH_NUM_FEATURES];
    static float vec3[SYRTH_NUM_FEATURES];
    static float vec4[SYRTH_NUM_FEATURES];

    vec1[0] = 1.0f; vec1[11] = 1.0f; vec1[20] = 1.0f;    /* SQL sink */
    vec1[27] = 1.0f; vec1[29] = 1.0f; vec1[39] = 1.0f;
    vec2[0] = 1.0f; vec2[23] = 1.0f; vec2[30] = 1.0f;    /* os.system */
    vec3[0] = 1.0f; vec3[21] = 1.0f; vec3[28] = 1.0f;    /* render */
    /* vec4 stays all zeros */

    const float* patterns[4] = {vec1, vec2, vec3, vec4};
    int cls;
    float conf;

    /* Extended warmup */
    for (int i = 0; i < 50; i++) {
        int p = i % 4;
        cls = benchmark_iteration(patterns[p], SYRTH_NUM_FEATURES, &conf);
    }

    double times_ns[10];

    for (int run = 0; run < 10; run++) {
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);

        for (int i = 0; i < n; i++) {
            int p = i % 4;
            benchmark_iteration(patterns[p], SYRTH_NUM_FEATURES, &conf);
        }

        clock_gettime(CLOCK_MONOTONIC, &end);
        double elapsed_ns = ((double)(end.tv_sec - start.tv_sec)) * 1e9 +
                            ((double)(end.tv_nsec - start.tv_nsec));
        times_ns[run] = elapsed_ns / (double) n;
    }

    double min_ns = times_ns[0], max_ns = times_ns[0], sum_ns = 0;
    for (int i = 0; i < 10; i++) {
        if (times_ns[i] < min_ns) min_ns = times_ns[i];
        if (times_ns[i] > max_ns) max_ns = times_ns[i];
        sum_ns += times_ns[i];
    }
    double avg_ns = sum_ns / 10.0;

    double variance = 0;
    for (int i = 0; i < 10; i++) {
        variance += (times_ns[i] - avg_ns) * (times_ns[i] - avg_ns);
    }
    double std_ns = sqrt(variance / 10.0);

    printf("C_BENCHMARK_RESULTS\n");
    printf("runs_total: %d\n", n * 10);
    printf("per_call_avg_ns: %.2f\n", avg_ns);
    printf("per_call_min_ns: %.2f\n", min_ns);
    printf("per_call_max_ns: %.2f\n", max_ns);
    printf("per_call_std_ns: %.2f\n", std_ns);
    printf("throughput_sps: %.0f\n", 1e9 / avg_ns);
    printf("last_class: %d (%s)\n", cls, syrth_class_name(cls));
    printf("last_conf: %.4f\n", conf);

    return 0;
}