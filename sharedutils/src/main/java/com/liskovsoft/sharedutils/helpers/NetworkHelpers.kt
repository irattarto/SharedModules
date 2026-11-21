package com.liskovsoft.sharedutils.helpers

import info.guardianproject.netcipher.NetCipher
import java.net.HttpURLConnection
import java.net.URL
import javax.net.ssl.HttpsURLConnection

object NetworkHelpers {
    @JvmStatic
    fun getHttpsURLConnection(url: URL): HttpURLConnection {
        // Original value
        //val conn = url.openConnection() as HttpURLConnection
        val conn = getBestHttpsURLConnection(url)

        // Imitate 'keepAlive' = false (cause buffering?)
        // https://stackoverflow.com/questions/3352424/httpurlconnection-openconnection-fails-second-time/3943820#3943820
        //conn.setRequestProperty("connection", "close")

        return conn
    }

    // SmartFin: removed unused getDohURLConnection (connected by IP with a relaxed host check)

    private fun getBestHttpsURLConnection(url: URL): HttpsURLConnection = NetCipher.getCompatibleHttpsURLConnection(url)
}