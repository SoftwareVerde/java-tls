package com.softwareverde.security.tls;

import com.softwareverde.security.AuthorizationKeyFactory;
import com.softwareverde.util.ByteUtil;
import com.softwareverde.util.HexUtil;
import com.softwareverde.util.ReflectionUtil;

import javax.net.ssl.*;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;

public class TlsFactory {
    public static TlsCertificate loadTlsCertificate(final String certificate, final byte[] p12Key) {
        final AuthorizationKeyFactory authorizationKeyFactory = new AuthorizationKeyFactory();
        final char[] temporaryKeyStorePassword = authorizationKeyFactory.generateAuthorizationKey().toCharArray();

        final TlsCertificate tlsCertificate = new TlsCertificate();

        try {
            final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            {
                keyStore.load(null); // Create an empty store.

                final Certificate[] certificateChain;
                {
                    final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                    final BufferedInputStream certificateInputStream = new BufferedInputStream(new ByteArrayInputStream(certificate.getBytes()));
                    certificateChain = certificateFactory.generateCertificates(certificateInputStream).toArray(new java.security.cert.Certificate[0]);
                    for (final Certificate certificateChainItem : certificateChain) {
                        // System.out.println("Loaded Certificate: " + ((X509Certificate) certificateChainItem).getSubjectX500Principal().getName());
                    }
                    certificateInputStream.close();

                    Integer certificateIndex = 0;
                    for (final Certificate cert : certificateChain) {
                        final String alias = "certificate" + (certificateIndex > 0 ? certificateIndex : "");
                        keyStore.setCertificateEntry(alias, cert);
                        certificateIndex += 1;
                    }
                    tlsCertificate._certificates = certificateChain;
                }

                if (p12Key != null) {
                    final InputStream keyFileInputStream = new ByteArrayInputStream(p12Key);
                    final KeyStore privateKeyKeyStore = KeyStore.getInstance("PKCS12");
                    privateKeyKeyStore.load(keyFileInputStream, null);
                    keyFileInputStream.close();

                    final Enumeration<String> keyAliases = privateKeyKeyStore.aliases();
                    while (keyAliases.hasMoreElements()) {
                        final String alias = keyAliases.nextElement();
                        if (privateKeyKeyStore.isKeyEntry(alias)) {
                            final Key privateKey = privateKeyKeyStore.getKey(alias, null);
                            keyStore.setKeyEntry(alias, privateKey, temporaryKeyStorePassword, certificateChain);
                        }
                    }
                }
            }

            {
                KeyManagerFactory keyManagerFactory = null;
                TrustManagerFactory trustManagerFactory = null;

                try {
                    keyManagerFactory = KeyManagerFactory.getInstance("X509");
                    trustManagerFactory = TrustManagerFactory.getInstance("X509");
                }
                catch (final NoSuchAlgorithmException noSuchAlgorithmException) {
                    keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
                    trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
                }

                keyManagerFactory.init(keyStore, temporaryKeyStorePassword);
                trustManagerFactory.init(keyStore);

                tlsCertificate._keyManagerFactory = keyManagerFactory;
                tlsCertificate._trustManagerFactory = trustManagerFactory;
            }

            return tlsCertificate;
        }
        catch (final Exception exception) {
            throw new TlsFactoryException(exception);
        }
    }

    public static SSLContext createContext(final TlsCertificate... tlsCertificates) {
        try {
            final SSLContext sslContext = ServerSSLContextWithSNI.newInstance(); // SSLContext.getInstance("TLS");

            final ArrayList<KeyManager> keyManagerList = new ArrayList<KeyManager>();
            final ArrayList<TrustManager> trustManagerList = new ArrayList<TrustManager>();
            // final ArrayList<SNIMatcher> matchers = new ArrayList<SNIMatcher>();

            for (final TlsCertificate tlsCertificate : tlsCertificates) {
                for (final KeyManager keyManager : tlsCertificate._keyManagerFactory.getKeyManagers()) {
                    if (! (keyManager instanceof X509KeyManager)) { continue; }

                    final X509KeyManager coreKeyManager = (X509KeyManager) keyManager;
                    keyManagerList.add(new KeyManagerWrapper(coreKeyManager));
                }

                for (final TrustManager trustManager : tlsCertificate._trustManagerFactory.getTrustManagers()) {
                    trustManagerList.add(trustManager);
                }

                // matchers.addAll(TlsCertificate.getSniMatchers(tlsCertificate));
            }

            sslContext.init(keyManagerList.toArray(new KeyManager[0]), trustManagerList.toArray(new TrustManager[0]), null);
            final SSLParameters sslParameters = sslContext.getDefaultSSLParameters();
            // final SNIMatcher matcher = SNIHostName.createSNIMatcher("(.*)*"); // SNIHostName.createSNIMatcher("(.*\\.)*example\\.com");
            // sslParameters.setSNIMatchers(matchers);
            return sslContext;
        }
        catch (final Exception exception) {
            exception.printStackTrace();
            throw new TlsFactoryException(exception);
        }
    }
}

class ServerSSLContextWithSNI extends SSLContext {
    public static final String CORE_SPI_MEMBER_NAME = "contextSpi";
    public static final String PROVIDER_MEMBER_NAME = "provider";
    public static final String PROTOCOL_MEMBER_NAME = "protocol";

    public static ServerSSLContextWithSNI newInstance() {
        try {
            final SSLContext core = SSLContext.getInstance("TLS");
            return new ServerSSLContextWithSNI(core);
        }
        catch (final Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    protected final SSLContext _core;
    protected final SSLContextSpiWithSNI _coreSpi;

    public ServerSSLContextWithSNI(final SSLContext core) {
        super(new SSLContextSpiWithSNI(core), (Provider) ReflectionUtil.getValue(core, PROVIDER_MEMBER_NAME), (String) ReflectionUtil.getValue(core, PROTOCOL_MEMBER_NAME));
        _core = core;
        _coreSpi = ReflectionUtil.getValue(this, CORE_SPI_MEMBER_NAME);
    }
}

class SSLContextSpiWithSNI extends SSLContextSpi {
    protected final SSLContextSpi _core;

    public SSLContextSpiWithSNI(final SSLContext coreSslContext) {
        _core = ReflectionUtil.getValue(coreSslContext, ServerSSLContextWithSNI.CORE_SPI_MEMBER_NAME);
    }

    @Override
    protected void engineInit(final KeyManager[] keyManagers, final TrustManager[] trustManagers, final SecureRandom secureRandom) throws KeyManagementException {
        try {
            final Method method = SSLContextSpi.class.getDeclaredMethod("engineInit", KeyManager[].class, TrustManager[].class, SecureRandom.class);
            method.setAccessible(true);
            method.invoke(_core, keyManagers, trustManagers, secureRandom);
        }
        catch (final Exception exception) {
            exception.printStackTrace();
        }
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {
        try {
            return ReflectionUtil.invoke(_core, "engineGetSocketFactory");
        }
        catch (final Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        try {
            return ReflectionUtil.invoke(_core, "engineGetServerSocketFactory");
        }
        catch (final Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {
        try {
            final SSLEngine coreSSLEngine = ReflectionUtil.invoke(_core, "engineCreateSSLEngine");
            return new SSLEngineWithSni(coreSSLEngine);
        }
        catch (final Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(final String host, final int port) {
        try {
            final Method method = SSLContextSpi.class.getDeclaredMethod("engineCreateSSLEngine", String.class, int.class);
            method.setAccessible(true);
            final SSLEngine coreSSLEngine = (SSLEngine) (method.invoke(_core, host, port));
            // System.out.println(coreSSLEngine);
            return new SSLEngineWithSni(coreSSLEngine);
        }
        catch (final Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    protected SSLSessionContext engineGetServerSessionContext() {
        try {
            return ReflectionUtil.invoke(_core, "engineGetServerSessionContext");
        }
        catch (final Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext() {
        try {
            return ReflectionUtil.invoke(_core, "engineGetClientSessionContext");
        }
        catch (final Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }
}

class SSLEngineWithSni extends SSLEngine {
    protected final SSLEngine _core;

    public SSLEngineWithSni(final SSLEngine sslEngine) {
        super(sslEngine.getPeerHost(), sslEngine.getPeerPort());
        _core = sslEngine;
        System.out.println("SSLEngineWithSni::constructor");
    }

    @Override
    public SSLEngineResult wrap(final ByteBuffer[] byteBuffers, final int i, final int i1, final ByteBuffer byteBuffer) throws SSLException {
        System.out.println("SSLEngineWithSni::wrap");
        return _core.wrap(byteBuffers, i, i1, byteBuffer);
    }

    static final Object mutux = new Object();
    @Override
    public synchronized SSLEngineResult unwrap(final ByteBuffer byteBuffer, final ByteBuffer[] appData, final int index, final int length) throws SSLException {
        System.out.println("SSLEngineWithSni::unwrap");
        synchronized (mutux) {
        try {
            final int position = byteBuffer.position();
            // final int available = byteBuffer.limit();
            // final ByteBuffer copiedByteBuffer = byteBuffer.duplicate();
            final byte[] bytes = byteBuffer.array();

            // final int headerByteCount = 5;
            // final int initializationVectorByteCount = 256;

            // if (available >= (headerByteCount + initializationVectorByteCount)) {
                // final int payloadIndex = (headerByteCount + initializationVectorByteCount);
                // final int payloadAvailable = (available - payloadIndex);

            System.out.println(HexUtil.toHexString(ByteUtil.copyBytes(bytes, (position), 256)));
            final byte HANDSHAKE_MESSAGE_TYPE = 0x16;
            final byte HANDSHAKE_MESSAGE_CLIENT_HELLO = 0x01;
            final int SERVER_NAME_EXTENSION = 0x00;
            final int headerByteCount = 5;
            final int maxMessageLength = (1 << 16);
            final byte messageType = bytes[position];
            final byte[] version = ByteUtil.copyBytes(bytes, position + 1, 2);
            final int messageLength = ByteUtil.bytesToInteger(ByteUtil.copyBytes(bytes, position + 3, 2));
            System.out.println("MessageType: " + HexUtil.toHexString(new byte[]{ messageType }));
            System.out.println("Version: " + HexUtil.toHexString(version));
            System.out.println("MessageLength: " + messageLength + " MAX=" + maxMessageLength);
            if ( (messageType == HANDSHAKE_MESSAGE_TYPE) && (messageLength < maxMessageLength) ) {

                final byte[] handshakeMessage = ByteUtil.copyBytes(bytes, (position + headerByteCount), (messageLength - headerByteCount));
                final byte handshakeMessageType = handshakeMessage[0];
                int currentIndex = 1;

                System.out.println("HandshakeType: " + handshakeMessageType);

                if (handshakeMessageType == HANDSHAKE_MESSAGE_CLIENT_HELLO) {
                    System.out.println("HandshakeLength: " + ByteUtil.bytesToInteger(ByteUtil.copyBytes(handshakeMessage, currentIndex, 3)));
                    currentIndex += 3; // Handshake Message Length....

                    System.out.println("TLS Version: " + HexUtil.toHexString(ByteUtil.copyBytes(handshakeMessage, currentIndex, 2)));
                    currentIndex += 2; // SSL/TLS Version

                    currentIndex += 32; // Random Nonce...

                    final int sessionIdByteCount = ByteUtil.bytesToInteger(ByteUtil.copyBytes(handshakeMessage, currentIndex, 1));
                    currentIndex += (sessionIdByteCount + 1);
                    System.out.println(currentIndex);

                    final int ciphersByteCount = ByteUtil.bytesToInteger(ByteUtil.copyBytes(handshakeMessage, currentIndex, 2));
                    currentIndex += (ciphersByteCount + 2);
                    System.out.println(currentIndex);

                    final int compressionMethodsByteCount = ByteUtil.bytesToInteger(ByteUtil.copyBytes(handshakeMessage, currentIndex, 1));
                    currentIndex += (compressionMethodsByteCount + 1);
                    System.out.println(currentIndex);

                    final boolean hasExtensions = (currentIndex < messageLength);
                    System.out.println(currentIndex + " < " + messageLength);

                    if (hasExtensions) {
                        final int totalExtensionByteCount = ByteUtil.bytesToInteger(ByteUtil.copyBytes(handshakeMessage, currentIndex, 2));
                        currentIndex += 2;
                        System.out.println("TotalExtensionLength: " + totalExtensionByteCount);

                        do {
                            final int extensionId = ByteUtil.bytesToInteger(ByteUtil.copyBytes(handshakeMessage, currentIndex, 2));
                            currentIndex += 2;
                            System.out.println("ExtensionType: " + extensionId);

                            final int extensionLength = ByteUtil.bytesToInteger(ByteUtil.copyBytes(handshakeMessage, currentIndex, 2));
                            currentIndex +=2 ;

                            if (extensionId == SERVER_NAME_EXTENSION) {
                                final int listLength = ByteUtil.bytesToInteger(ByteUtil.copyBytes(handshakeMessage, currentIndex, 2));
                                currentIndex += 2;
                                System.out.println("ServerNameExtensionLength: " + listLength);

                                final int type = ByteUtil.bytesToInteger(ByteUtil.copyBytes(handshakeMessage, currentIndex, 1));
                                currentIndex += 1;
                                System.out.println("ServerNameExtensionType: " + type);

                                final int nameByteCount = ByteUtil.bytesToInteger(ByteUtil.copyBytes(handshakeMessage, currentIndex, 2));
                                currentIndex += 2;
                                System.out.println("ServerNameExtensionNameLength: " + nameByteCount);
                                if (nameByteCount > (maxMessageLength)) { break; }

                                final byte[] serverNameBytes = ByteUtil.copyBytes(handshakeMessage, currentIndex, nameByteCount);
                                currentIndex += nameByteCount;
                                System.out.println("ServerName: " + new String(serverNameBytes));
                            }
                            else {
                                currentIndex += extensionLength;
                            }
                        } while(currentIndex < messageLength);
                    }

//                    // System.out.println(new String(bytes));
//                    final byte[] localhost = new String("pool.localhost").getBytes();
//                    // final byte[] poolLocalhost = new String("pool.localhost").getBytes();
//                    final int matchLength = localhost.length;
//                    int currentMatchLength = 0;
//                    Integer matchStart = null;
//                    for (int i = 0; i < handshakeMessage.length; ++i) {
//                        final byte bufferByte = handshakeMessage[i];
//                        final byte localhostByte = localhost[currentMatchLength];
//                        if (bufferByte == localhostByte) {
//                            currentMatchLength += 1;
//                        }
//
//                        if (currentMatchLength >= matchLength) {
//                            matchStart = (i - (matchLength - 1));
//                            break;
//                        }
//                    }
//
//                    if (matchStart != null) {
//                        final byte[] match = new byte[matchLength];
//                        for (int i = 0; i < matchLength; ++i) {
//                            match[i] = handshakeMessage[matchStart + i];
//                        }
//                        System.out.println(new String(match));
//
//
//                        final byte[] preBytes = new byte[4];
//                        for (int i = 0; i < 4; ++i) {
//                            preBytes[i] = handshakeMessage[matchStart + i];
//                        }
//                        System.out.println(HexUtil.toHexString(preBytes));
//                    }
                }
            }
        }
        catch (final Exception exception) {
            exception.printStackTrace();
        }
        }

//            final ArrayList<SNIMatcher> sniMatchers = new ArrayList<SNIMatcher>(1) {
//                @Override
//                public boolean isEmpty() {
//                    (new Exception()).printStackTrace();
//                    return super.isEmpty();
//                }
//            };
//            sniMatchers.add(new SNIMatcher(0) {
//                @Override
//                public boolean matches(final SNIServerName sniServerName) {
//                    System.out.println("SNIMatcher: " + sniServerName);
//                    return true;
//                }
//            });
//            try {
//                ReflectionUtil.setValue(handshaker, "sniMatchers", sniMatchers);
//                System.out.println("SET sniMatchers");
//            }
//            catch (final Exception e) { e.printStackTrace(); }
//        }
//        else {
//            System.out.println("handshaker null");
//        }


        return _core.unwrap(byteBuffer, appData, index, length);
    }

    @Override
    public Runnable getDelegatedTask() {
        System.out.println("SSLEngineWithSni::getDelegatedTask");
        return _core.getDelegatedTask();
    }

    @Override
    public void closeInbound() throws SSLException {
        System.out.println("SSLEngineWithSni::closeInbound");
        _core.closeInbound();
    }

    @Override
    public boolean isInboundDone() {
        System.out.println("SSLEngineWithSni::isInboundDone");
        return _core.isInboundDone();
    }

    @Override
    public void closeOutbound() {
        System.out.println("SSLEngineWithSni::closeOutbound");
        _core.closeOutbound();
    }

    @Override
    public boolean isOutboundDone() {
        System.out.println("SSLEngineWithSni::isOutboundDone");
        return _core.isOutboundDone();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        System.out.println("SSLEngineWithSni::getSupportedCipherSuites");
        return _core.getSupportedCipherSuites();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        System.out.println("SSLEngineWithSni::getEnabledCipherSuites");
        return _core.getEnabledCipherSuites();
    }

    @Override
    public void setEnabledCipherSuites(final String[] strings) {
        System.out.println("SSLEngineWithSni::setEnabledCipherSuites");
        _core.setEnabledCipherSuites(strings);
    }

    @Override
    public String[] getSupportedProtocols() {
        System.out.println("SSLEngineWithSni::getSupportedProtocols");
        return _core.getSupportedProtocols();
    }

    @Override
    public String[] getEnabledProtocols() {
        System.out.println("SSLEngineWithSni::getEnabledProtocols");
        return _core.getEnabledProtocols();
    }

    @Override
    public void setEnabledProtocols(final String[] strings) {
        System.out.println("SSLEngineWithSni::setEnabledProtocols");
        _core.setEnabledProtocols(strings);
    }

    @Override
    public SSLSession getSession() {
        System.out.println("SSLEngineWithSni::getSession");
        return _core.getSession();
    }

    @Override
    public void beginHandshake() throws SSLException {
        System.out.println("SSLEngineWithSni::beginHandshake");
        _core.beginHandshake();
    }

    @Override
    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        System.out.println("SSLEngineWithSni::getHandshakeStatus");
        return _core.getHandshakeStatus();
    }

    @Override
    public void setUseClientMode(final boolean b) {
        System.out.println("SSLEngineWithSni::setUseClientMode");
        _core.setUseClientMode(b);
    }

    @Override
    public boolean getUseClientMode() {
        System.out.println("SSLEngineWithSni::getUseClientMode");
        return _core.getUseClientMode();
    }

    @Override
    public void setNeedClientAuth(final boolean b) {
        System.out.println("SSLEngineWithSni::setNeedClientAuth");
        _core.setNeedClientAuth(b);
    }

    @Override
    public boolean getNeedClientAuth() {
        System.out.println("SSLEngineWithSni::getNeedClientAuth");
        return _core.getNeedClientAuth();
    }

    @Override
    public void setWantClientAuth(final boolean b) {
        System.out.println("SSLEngineWithSni::setWantClientAuth");
        _core.setWantClientAuth(b);
    }

    @Override
    public boolean getWantClientAuth() {
        System.out.println("SSLEngineWithSni::getWantClientAuth");
        return _core.getWantClientAuth();
    }

    @Override
    public void setEnableSessionCreation(final boolean b) {
        System.out.println("SSLEngineWithSni::setEnabledSessionCreation");
        _core.setEnableSessionCreation(b);
    }

    @Override
    public boolean getEnableSessionCreation() {
        System.out.println("SSLEngineWithSni::getEnableSessionCreation");
        return _core.getEnableSessionCreation();
    }

    @Override
    public void setSSLParameters(final SSLParameters sslParameters) {
        System.out.println("SSLEngineWithSni::setSSLParameters");
        (new Exception()).printStackTrace();
        final ArrayList<SNIMatcher> sniMatchers = new ArrayList<SNIMatcher>(1);
        sniMatchers.add(new SNIMatcher(0) {
            @Override
            public boolean matches(final SNIServerName sniServerName) {
                System.out.println("SNIMatcher: " + sniServerName);
                return true;
            }
        });
        sslParameters.setSNIMatchers(sniMatchers);
        super.setSSLParameters(sslParameters);
    }
}


class KeyManagerWrapper extends X509ExtendedKeyManager {
    protected final X509KeyManager _core;

    public KeyManagerWrapper(final X509KeyManager coreKeyManager) {
        _core = coreKeyManager;
    }

    @Override
    public String[] getClientAliases(final String s, final Principal[] principals) {
        // System.out.println("getClientAliases");
        return _core.getClientAliases(s, principals);
    }

    @Override
    public String chooseClientAlias(final String[] strings, final Principal[] principals, final Socket socket) {
        System.out.println("chooseClientAlias");
        for (final String string : strings) {
            // System.out.println(string);
        }
        // System.out.println();
        for (final SNIServerName serverName : ((SSLSocket) socket).getSSLParameters().getServerNames()) {
            // System.out.println(serverName);
        }
        return _core.chooseClientAlias(strings, principals, socket);
    }

    @Override
    public String[] getServerAliases(final String s, final Principal[] principals) {
        System.out.println("getServerAliases");
        return _core.getServerAliases(s, principals);
    }

    @Override
    public String chooseServerAlias(final String s, final Principal[] principals, final Socket socket) {
        System.out.println("chooseServerAlias");
        return _core.chooseServerAlias(s, principals, socket);
    }

    @Override
    public X509Certificate[] getCertificateChain(final String s) {
        // System.out.println("getCertificateChain");
        return _core.getCertificateChain(s);
    }

    @Override
    public PrivateKey getPrivateKey(final String s) {
        // System.out.println("getPrivateKey");
        return _core.getPrivateKey(s);
    }

    @Override
    public String chooseEngineClientAlias(final String[] keyType, final Principal[] issuers, final SSLEngine engine) {
        System.out.println("chooseEngineClientAlias");
        if (_core instanceof X509ExtendedKeyManager) {
            return ((X509ExtendedKeyManager) _core).chooseEngineClientAlias(keyType, issuers, engine);
        }
        return null;
    }

    @Override
    public String chooseEngineServerAlias(final String keyType, final Principal[] issuers, final SSLEngine engine) {
        System.out.println("chooseEngineServerAlias: " + keyType + ", " + issuers + ", " + engine.getPeerHost() + ":" + engine.getPeerPort());
        // System.out.println("ServerNames: ");
        for (final SNIServerName serverName : engine.getSSLParameters().getServerNames()) {
            // System.out.println(serverName);
        }
        // System.out.println(engine.getSSLParameters().getSNIMatchers().size());
        for (final SNIMatcher sniMatcher : engine.getSSLParameters().getSNIMatchers()) {
            // System.out.println(sniMatcher + " " + sniMatcher.getType());
        }

        for (final String valueName : engine.getSession().getValueNames()) {
            // System.out.println("SSL Session Values: " + valueName + "=" + engine.getSession().getValue(valueName));
        }

        if (_core instanceof X509ExtendedKeyManager) {
            // System.out.println("chooseEngineServerAlias: " + ((X509ExtendedKeyManager) _core).chooseEngineServerAlias(keyType, issuers, engine));
            return ((X509ExtendedKeyManager) _core).chooseEngineServerAlias(keyType, issuers, engine);
        }
        return null;
    }
}