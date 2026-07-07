
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include "../syrth_engine.h"

// Prevent function inlining for consistent measurements
static int __attribute__((noinline)) benchmark_iteration(
    const char** tokens, int num_tokens, int* cls, float* conf
) {
    syrth_predict(tokens, num_tokens, cls, conf);
    return *cls;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <num_iterations>\n", argv[0]);
        return 1;
    }

    int n = atoi(argv[1]);
    if (n < 1) n = 100;

    // Multiple test patterns for comprehensive benchmarking
    const char* pattern1[] = {"def:get_user", "arg:user_input", "sink:execute", "query:SELECT", "data:user_data"};
    const char* pattern2[] = {"arg:sql_query", "sink:cursor.execute", "data:unsanitized"};
    const char* pattern3[] = {"arg:user_input", "sink:render_template", "context:html"};
    const char* pattern4[] = {"arg:url", "sink:requests.get", "data:internal_response"};
    
    int pattern_lens[] = {5, 3, 3, 3};
    const char** patterns[] = {pattern1, pattern2, pattern3, pattern4};
    int num_patterns = 4;

    int cls;
    float conf;
    
    // Extended warmup
    for (int i = 0; i < 50; i++) {
        int p = i % num_patterns;
        benchmark_iteration(patterns[p], pattern_lens[p], &cls, &conf);
    }

    // High-resolution timing with multiple runs for statistics
    double times_ns[10];
    
    for (int run = 0; run < 10; run++) {
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);

        for (int i = 0; i < n; i++) {
            int p = i % num_patterns;
            benchmark_iteration(patterns[p], pattern_lens[p], &cls, &conf);
        }

        clock_gettime(CLOCK_MONOTONIC, &end);
        
        double elapsed_ns = (end.tv_sec - start.tv_sec) * 1e9 +
                           (end.tv_nsec - start.tv_nsec);
        times_ns[run] = elapsed_ns / n;
    }

    // Calculate statistics
    double min_ns = times_ns[0], max_ns = times_ns[0], sum_ns = 0;
    for (int i = 0; i < 10; i++) {
        if (times_ns[i] < min_ns) min_ns = times_ns[i];
        if (times_ns[i] > max_ns) max_ns = times_ns[i];
        sum_ns += times_ns[i];
    }
    double avg_ns = sum_ns / 10;
    
    // Calculate std dev
    double variance = 0;
    for (int i = 0; i < 10; i++) {
        variance += (times_ns[i] - avg_ns) * (times_ns[i] - avg_ns);
    }
    double std_ns = sqrt(variance / 10);

    printf("C_BENCHMARK_RESULTS\n");
    printf("runs_total: %d\n", n * 10);
    printf("per_call_avg_ns: %.2f\n", avg_ns);
    printf("per_call_min_ns: %.2f\n", min_ns);
    printf("per_call_max_ns: %.2f\n", max_ns);
    printf("per_call_std_ns: %.2f\n", std_ns);
    printf("throughput_sps: %.0f\n", 1e9 / avg_ns);
    printf("last_class: %d\n", cls);
    printf("last_conf: %.4f\n", conf);

    return 0;
}
