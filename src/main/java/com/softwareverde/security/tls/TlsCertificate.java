package com.softwareverde.security.tls;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.security.cert.Certificate;

public class TlsCertificate {
    protected Certificate[] _certificates;

    protected KeyManagerFactory _keyManagerFactory;
    protected TrustManagerFactory _trustManagerFactory;

    public Certificate[] getCertificates() {
        return _certificates;
    }
}
