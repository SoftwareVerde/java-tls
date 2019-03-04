package com.softwareverde.security.tls;

import com.softwareverde.util.StringUtil;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class TlsCertificate {
    public static List<String> getHostNames(final TlsCertificate tlsCertificate) {
        final ArrayList<String> hostNames = new ArrayList<String>();
        for (final Certificate certificate : tlsCertificate.getCertificates()) {
            final X509Certificate x509Certificate = (X509Certificate) certificate;
            final X500Principal x500Principal = x509Certificate.getSubjectX500Principal();
            final String subjectName = x500Principal.getName();
            final List<String> domainNameMatches = StringUtil.pregMatch("^.*CN=([^,]+).*$", subjectName);
            if (domainNameMatches.size() == 0) { continue; }

            final String domainName = domainNameMatches.get(0);
            hostNames.add(domainName);
            System.out.println(domainName);
        }
        return hostNames;
    }

    public static List<SNIMatcher> getSniMatchers(final TlsCertificate tlsCertificate) {
        final ArrayList<SNIMatcher> sniMatchers = new ArrayList<SNIMatcher>();
        for (final String hostName : TlsCertificate.getHostNames(tlsCertificate)) {
            // final SNIMatcher sniMatcher = SNIHostName.createSNIMatcher("^" + hostName + "$");
            // System.out.println("Creating Matcher: " + "^" + hostName + "$");
            final SNIMatcher sniMatcher = SNIHostName.createSNIMatcher(hostName);
            System.out.println("Creating Matcher: " + hostName);
            sniMatchers.add(sniMatcher);
        }
        return sniMatchers;
    }

    protected Certificate[] _certificates;

    protected KeyManagerFactory _keyManagerFactory;
    protected TrustManagerFactory _trustManagerFactory;

    public Certificate[] getCertificates() {
        return _certificates;
    }
}
