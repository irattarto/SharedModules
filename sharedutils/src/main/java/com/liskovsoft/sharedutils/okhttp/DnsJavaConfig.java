package com.liskovsoft.sharedutils.okhttp;

import android.content.Context;

/**
 * SmartFin: dnsjava 3 reads the system DNS configuration through a Context on Android.
 * Call {@link #init(Context)} once at app start (kept separate so callers don't need OkHttp/dnsjava on their classpath).
 */
public final class DnsJavaConfig {
    private DnsJavaConfig() {
    }

    public static void init(Context context) {
        try {
            org.xbill.DNS.config.AndroidResolverConfigProvider.setContext(context.getApplicationContext());
        } catch (Throwable ignored) {
            // dnsjava missing or API changed - Lookup falls back to its default config
        }
    }
}
