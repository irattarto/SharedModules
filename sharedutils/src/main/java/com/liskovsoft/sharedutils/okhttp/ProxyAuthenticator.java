package com.liskovsoft.sharedutils.okhttp;

import java.net.Authenticator;
import java.net.InetAddress;
import java.net.PasswordAuthentication;

/**
 * SmartFin: global {@link Authenticator} that hands the proxy credentials to the configured proxy only.<br/>
 * Before, the credentials were returned for any request - including a web server answering 401 - which could leak them.<br/>
 * HTTP proxies ask with {@link RequestorType#PROXY}. SOCKS5 authentication (java.net.SocksSocketImpl) asks with the
 * default {@link RequestorType#SERVER}, so it is accepted only when protocol, host and port match the configured proxy.
 */
public class ProxyAuthenticator extends Authenticator {
    private final String mUser;
    private final char[] mPassword;
    private final String mProxyHost;
    private final int mProxyPort;

    public ProxyAuthenticator(String user, String password, String proxyHost, int proxyPort) {
        mUser = user;
        mPassword = password.toCharArray();
        mProxyHost = proxyHost;
        mProxyPort = proxyPort;
    }

    @Override
    protected PasswordAuthentication getPasswordAuthentication() {
        if (getRequestorType() == RequestorType.PROXY || isSocksRequestFromProxy()) {
            return new PasswordAuthentication(mUser, mPassword.clone());
        }
        return null;
    }

    private boolean isSocksRequestFromProxy() {
        String protocol = getRequestingProtocol();
        if (protocol == null || !protocol.toUpperCase().startsWith("SOCKS")) {
            return false;
        }
        if (mProxyPort > 0 && getRequestingPort() != mProxyPort) {
            return false;
        }
        if (mProxyHost == null) {
            return false;
        }
        if (mProxyHost.equalsIgnoreCase(getRequestingHost())) {
            return true;
        }
        InetAddress site = getRequestingSite();
        return site != null && (mProxyHost.equals(site.getHostAddress()) || mProxyHost.equalsIgnoreCase(site.getHostName()));
    }
}
