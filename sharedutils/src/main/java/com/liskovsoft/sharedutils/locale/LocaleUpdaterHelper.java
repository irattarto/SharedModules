package com.liskovsoft.sharedutils.locale;

import android.content.Context;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.os.LocaleList;

import java.util.Locale;
import java.util.StringTokenizer;

class LocaleUpdaterHelper {
    // short lang code. ex: "ru"
    public static void forceLocale(Context context, String langCode) {
        if (langCode == null || langCode.isEmpty()) {
            return;
        }

        Locale locale = parseLangCode(langCode);
        Locale oldLocale = Locale.getDefault();
        if (oldLocale.equals(locale)) {
            return;
        }

        Locale.setDefault(locale);
        Resources resources = context.getResources();
        Configuration config = resources.getConfiguration();
        config.locale = locale;

        config.setLocales(new LocaleList(locale));

        resources
                .updateConfiguration(
                        config,
                        resources.getDisplayMetrics()
                );
    }

    public static Locale parseLangCode(String langCode) {
        if (langCode == null) {
            return null;
        }

        StringTokenizer tokenizer = new StringTokenizer(langCode, "_");
        String lang = tokenizer.nextToken();
        String country = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : "";
        return new Locale(lang, country);
    }

    public static String getDefaultLocale() {
        Locale defaultLocale = Locale.getDefault();
        String lang = defaultLocale.getLanguage();
        String country = defaultLocale.getCountry();

        if (country == null || country.isEmpty()) {
            return String.format("%s", lang);
        }

        return String.format("%s_%S", lang, country);
    }
}
