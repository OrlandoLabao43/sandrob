/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.sandrob.android.net.http;

import android.content.Context;
import android.util.Log;



import org.apache.harmony.xnet.provider.jsse.FileClientSessionCache;
import org.apache.harmony.xnet.provider.jsse.SSLClientSessionCache;
import org.apache.harmony.xnet.provider.jsse.SSLContextImpl;
import org.apache.http.Header;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpStatus;
import org.apache.http.ParseException;
import org.apache.http.ProtocolVersion;
import org.apache.http.StatusLine;
import org.apache.http.message.BasicHttpRequest;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;
import org.sandrob.bouncycastle.asn1.x509.X509Name;
import org.sandrob.bouncycastle.openssl.PasswordFinder;
import org.sandrob.bouncycastle.openssl.PEMReader;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Vector;

/**
 * A Connection connecting to a secure http server or tunneling through
 * a http proxy server to a https server.
 *
 * @hide
 */
public class HttpsConnection extends Connection {

    /**
     * SSL socket factory
     */
    private static SSLSocketFactory mSslSocketFactory = null;

    private static SslClientCertificate mSslClientCertificate = null; 

    static {
        // This initialization happens in the zygote. It triggers some
        // lazy initialization that can will benefit later invocations of
        // initializeEngine().
    }
    
    // TODO: sandrob move this to cert utils file
    private static String getCertificateAlias(X509Certificate cert)
	{
		X500Principal subject = cert.getSubjectX500Principal();
		X500Principal issuer = cert.getIssuerX500Principal();

		String sSubjectCN = getCommonName(subject);

		// Could not get a subject CN - return blank
		if (sSubjectCN == null)
		{
			return "";
		}

		String sIssuerCN = getCommonName(issuer);

		// Self-signed certificate or could not get an issuer CN
		if (subject.equals(issuer) || sIssuerCN == null)
		{
			// Alias is the subject CN
			return sSubjectCN;
		}
		// else non-self-signed certificate
		// Alias is the subject CN followed by the issuer CN in parenthesis
		return MessageFormat.format("{0} ({1})", sSubjectCN, sIssuerCN);
	}
    
    /**
	 * Gets the common name from the given X500Principal.
	 * 
	 * @param name the X.500 principal
	 * @return the common name, null if not found
	 */
	private static String getCommonName(X500Principal name)
	{
		if (name == null)
		{
			return null;
		}

		return getCommonName(new X509Name(name.getName()));
	}
    
    /**
	 * Gets the common name from the given X509Name.
	 * 
	 * @param name the X.509 name
	 * @return the common name, null if not found
	 */
	private static String getCommonName(X509Name name)
	{
		if (name == null)
		{
			return null;
		}

		Vector<?> values = name.getValues(X509Name.CN);
		if (values == null || values.isEmpty())
		{
			return null;
		}

		return values.get(0).toString();
	}
	
	/**
	 * Find an unused alias in the keystore based on the given alias.
	 * 
	 * @param keyStore the keystore
	 * @param alias the alias
	 * @return alias that is not in use in the keystore
	 * @throws KeyStoreException
	 */
	private static String findUnusedAlias(KeyStore keyStore, String alias)
	    throws KeyStoreException
	{
		if (keyStore.containsAlias(alias))
		{
			int i = 1;
			while (true)
			{
				String nextAlias = alias + " (" + i + ")";
				if (!keyStore.containsAlias(nextAlias))
				{
					alias = nextAlias;
					break;
				}
			}
		}
		return alias;
	}

    /**
     * 
     *
     * @param sessionDir directory to cache SSL sessions
     * @param req request that call this function
     */
    public void initializeEngine(File sessionDir, Request req) {
        if (mSslSocketFactory == null){
        	String certificateFullPathName = null;
            String keyStoreType = "PKCS12";
            String keyStoreProvider = "BC";
            String certificatePassword = null;
	    	try {
	    		SSLClientSessionCache cache = null;
	    		KeyManager[] keyManagers = null;
	            KeyStore keyStore = null;
	            if (sessionDir != null) {
	                Log.d("HttpsConnection", "Caching SSL sessions in "
	                        + sessionDir + ".");
	                cache = FileClientSessionCache.usingDirectory(sessionDir);
	            }
	            
	            // Inform the user if we need ssl client settings
	            if (true) {

	            	synchronized (mSuspendLock) {
	                    mSuspended = true;
	                }
	                // don't hold the lock while calling out to the event handler
	                boolean canHandle = req.getEventHandler().handleSslClientSetingsRequest();
	                if(!canHandle) {
	                    throw new IOException("failed to handle ssl client settings ");
	                }
	                synchronized (mSuspendLock) {
	                    if (mSuspended) {
	                        try {
	                            // Put a limit on how long we are waiting; if the timeout
	                            // expires (which should never happen unless you choose
	                            // to ignore the SSL error dialog for a very long time),
	                            // we wake up the thread and abort the request. This is
	                            // to prevent us from stalling the network if things go
	                            // very bad.
	                            mSuspendLock.wait(10 * 60 * 1000);
	                            if (mSuspended) {
	                                // mSuspended is true if we have not had a chance to
	                                // restart the connection yet (ie, the wait timeout
	                                // has expired)
	                                mSuspended = false;
	                                mAborted = true;
	                                if (HttpLog.LOGV) {
	                                    HttpLog.v("HttpsConnection.openConnection():" +
	                                              " SSL timeout expired and request was cancelled!!!");
	                                }
	                            }
	                        } catch (InterruptedException e) {
	                            // ignore
	                        }
	                    }
	                    if (mAborted) {
	                        // The user decided not to use this unverified connection
	                        // so close it immediately.
	                        throw new SSLConnectionClosedByUserException("connection closed by the user");
	                    }
	                    if (mSslClientCertificate != null){
	                    	// we have some data about client certificate
	                    	certificateFullPathName = mSslClientCertificate.getCertificateFileName();
	                    	certificatePassword     = mSslClientCertificate.getCertificateFilePassword();
	                    }
	                }
	            }
	            
	            SSLContextImpl sslContext = new SSLContextImpl();
	            //SSLContext sslContext = SSLContext.getInstance("TLS");
	            if (certificateFullPathName != null && certificatePassword != null){
	            	File certFile = new File(certificateFullPathName);
	            	if (certFile.exists()){
						keyStore = KeyStore.getInstance(keyStoreType, keyStoreProvider);
						keyStore.load(new FileInputStream(new File(certificateFullPathName)),
								certificatePassword.toCharArray());
						
						String kmfa = KeyManagerFactory.getDefaultAlgorithm();
						KeyManagerFactory kmf = KeyManagerFactory.getInstance(kmfa);
						kmf.init(keyStore, certificatePassword.toCharArray());
						keyManagers = kmf.getKeyManagers();
	            	}
	            }
	            
	            // here, trust managers is a single trust-all manager
	            TrustManager[] trustManagers = new TrustManager[] {
	                new X509TrustManager() {
	                    public X509Certificate[] getAcceptedIssuers() {
	                        return null;
	                    }
	
	                    public void checkClientTrusted(
	                        X509Certificate[] certs, String authType) {
	                    }
	
	                    public void checkServerTrusted(
	                        X509Certificate[] certs, String authType) {
	                    }
	                }
	            };
	
	            sslContext.engineInit(keyManagers, trustManagers, null, cache, null);
	            //sslContext.init(keyManagers, trustManagers, null);
	            synchronized (HttpsConnection.class) {
	                mSslSocketFactory = sslContext.engineGetSocketFactory();
	            	//mSslSocketFactory = sslContext.getSocketFactory();
	            }
	        } catch (KeyManagementException e) {
	            throw new RuntimeException(e);
	        } catch (IOException e) {
	            throw new RuntimeException(e);
	        } catch (Exception e) {
	            throw new RuntimeException(e);
	        }
        }
    }

    private synchronized static SSLSocketFactory getSocketFactory() {
        return mSslSocketFactory;
    }

    /**
     * Object to wait on when suspending the SSL connection
     */
    private Object mSuspendLock = new Object();

    /**
     * True if the connection is suspended pending the result of asking the
     * user about an error.
     */
    private boolean mSuspended = false;

    /**
     * True if the connection attempt should be aborted due to an ssl
     * error.
     */
    private boolean mAborted = false;

    // Used when connecting through a proxy.
    private HttpHost mProxyHost;
    
    
    
    /**
     * Contructor for a https connection.
     */
    HttpsConnection(Context context, HttpHost host, HttpHost proxy,
                    RequestFeeder requestFeeder) {
        super(context, host, requestFeeder);
        mProxyHost = proxy;
    }

    /**
     * Sets the server SSL certificate associated with this
     * connection.
     * @param certificate The SSL certificate
     */
    /* package */ void setCertificate(SslCertificate certificate) {
        mCertificate = certificate;
    }
    
    void setClientCertificate(String certfilename, String password){
    	if (mSslClientCertificate == null){
    		if (certfilename != null && password != null){
    			mSslClientCertificate = new SslClientCertificate(certfilename, password);
    		}
    	}
    }

    /**
     * Opens the connection to a http server or proxy.
     *
     * @return the opened low level connection
     * @throws IOException if the connection fails for any reason.
     */
    @Override
    AndroidHttpClientConnection openConnection(Request req) throws IOException {
        SSLSocket sslSock = null;
        
        synchronized (HttpsConnection.class) {
        	initializeEngine(null, req);
        }
        if (mProxyHost != null) {
            // If we have a proxy set, we first send a CONNECT request
            // to the proxy; if the proxy returns 200 OK, we negotiate
            // a secure connection to the target server via the proxy.
            // If the request fails, we drop it, but provide the event
            // handler with the response status and headers. The event
            // handler is then responsible for cancelling the load or
            // issueing a new request.
            AndroidHttpClientConnection proxyConnection = null;
            Socket proxySock = null;
            try {
                proxySock = new Socket
                    (mProxyHost.getHostName(), mProxyHost.getPort());

                proxySock.setSoTimeout(60 * 1000);

                proxyConnection = new AndroidHttpClientConnection();
                HttpParams params = new BasicHttpParams();
                HttpConnectionParams.setSocketBufferSize(params, 8192);

                proxyConnection.bind(proxySock, params);
            } catch(IOException e) {
                if (proxyConnection != null) {
                    proxyConnection.close();
                }

                String errorMessage = e.getMessage();
                if (errorMessage == null) {
                    errorMessage =
                        "failed to establish a connection to the proxy";
                }

                throw new IOException(errorMessage);
            }

            StatusLine statusLine = null;
            int statusCode = 0;
            Headers headers = new Headers();
            try {
                BasicHttpRequest proxyReq = new BasicHttpRequest
                    ("CONNECT", mHost.toHostString());

                // add all 'proxy' headers from the original request
                for (Header h : req.mHttpRequest.getAllHeaders()) {
                    String headerName = h.getName().toLowerCase();
                    if (headerName.startsWith("proxy") || headerName.equals("keep-alive")) {
                        proxyReq.addHeader(h);
                    }
                }

                proxyConnection.sendRequestHeader(proxyReq);
                proxyConnection.flush();

                // it is possible to receive informational status
                // codes prior to receiving actual headers;
                // all those status codes are smaller than OK 200
                // a loop is a standard way of dealing with them
                do {
                    statusLine = proxyConnection.parseResponseHeader(headers);
                    statusCode = statusLine.getStatusCode();
                } while (statusCode < HttpStatus.SC_OK);
            } catch (ParseException e) {
                String errorMessage = e.getMessage();
                if (errorMessage == null) {
                    errorMessage =
                        "failed to send a CONNECT request";
                }

                throw new IOException(errorMessage);
            } catch (HttpException e) {
                String errorMessage = e.getMessage();
                if (errorMessage == null) {
                    errorMessage =
                        "failed to send a CONNECT request";
                }

                throw new IOException(errorMessage);
            } catch (IOException e) {
                String errorMessage = e.getMessage();
                if (errorMessage == null) {
                    errorMessage =
                        "failed to send a CONNECT request";
                }

                throw new IOException(errorMessage);
            }

            if (statusCode == HttpStatus.SC_OK) {
                try {
                    sslSock = (SSLSocket) getSocketFactory().createSocket(
                            proxySock, mHost.getHostName(), mHost.getPort(), true);
                } catch(IOException e) {
                    if (sslSock != null) {
                        sslSock.close();
                    }

                    String errorMessage = e.getMessage();
                    if (errorMessage == null) {
                        errorMessage =
                            "failed to create an SSL socket";
                    }
                    throw new IOException(errorMessage);
                }
            } else {
                // if the code is not OK, inform the event handler
                ProtocolVersion version = statusLine.getProtocolVersion();

                req.mEventHandler.status(version.getMajor(),
                                         version.getMinor(),
                                         statusCode,
                                         statusLine.getReasonPhrase());
                req.mEventHandler.headers(headers);
                req.mEventHandler.endData();

                proxyConnection.close();

                // here, we return null to indicate that the original
                // request needs to be dropped
                return null;
            }
        } else {
            // if we do not have a proxy, we simply connect to the host
            try {
                sslSock = (SSLSocket) getSocketFactory().createSocket();

                sslSock.setSoTimeout(SOCKET_TIMEOUT);
                sslSock.connect(new InetSocketAddress(mHost.getHostName(),
                        mHost.getPort()));
            } catch(IOException e) {
                if (sslSock != null) {
                    sslSock.close();
                }

                String errorMessage = e.getMessage();
                if (errorMessage == null) {
                    errorMessage = "failed to create an SSL socket";
                }

                throw new IOException(errorMessage);
            }
        }

        // do handshake and validate server certificates
        SslError error = CertificateChainValidator.getInstance().
            doHandshakeAndValidateServerCertificates(this, sslSock, mHost.getHostName());

        // Inform the user if there is a problem
        if (error != null) {
            // handleSslErrorRequest may immediately unsuspend if it wants to
            // allow the certificate anyway.
            // So we mark the connection as suspended, call handleSslErrorRequest
            // then check if we're still suspended and only wait if we actually
            // need to.
            synchronized (mSuspendLock) {
                mSuspended = true;
            }
            // don't hold the lock while calling out to the event handler
            boolean canHandle = req.getEventHandler().handleSslErrorRequest(error);
            if(!canHandle) {
                throw new IOException("failed to handle "+ error);
            }
            synchronized (mSuspendLock) {
                if (mSuspended) {
                    try {
                        // Put a limit on how long we are waiting; if the timeout
                        // expires (which should never happen unless you choose
                        // to ignore the SSL error dialog for a very long time),
                        // we wake up the thread and abort the request. This is
                        // to prevent us from stalling the network if things go
                        // very bad.
                        mSuspendLock.wait(10 * 60 * 1000);
                        if (mSuspended) {
                            // mSuspended is true if we have not had a chance to
                            // restart the connection yet (ie, the wait timeout
                            // has expired)
                            mSuspended = false;
                            mAborted = true;
                            if (HttpLog.LOGV) {
                                HttpLog.v("HttpsConnection.openConnection():" +
                                          " SSL timeout expired and request was cancelled!!!");
                            }
                        }
                    } catch (InterruptedException e) {
                        // ignore
                    }
                }
                if (mAborted) {
                    // The user decided not to use this unverified connection
                    // so close it immediately.
                    sslSock.close();
                    throw new SSLConnectionClosedByUserException("connection closed by the user");
                }
            }
        }

        // All went well, we have an open, verified connection.
        AndroidHttpClientConnection conn = new AndroidHttpClientConnection();
        BasicHttpParams params = new BasicHttpParams();
        params.setIntParameter(HttpConnectionParams.SOCKET_BUFFER_SIZE, 8192);
        conn.bind(sslSock, params);

        return conn;
    }

    /**
     * Closes the low level connection.
     *
     * If an exception is thrown then it is assumed that the connection will
     * have been closed (to the extent possible) anyway and the caller does not
     * need to take any further action.
     *
     */
    @Override
    void closeConnection() {
        // if the connection has been suspended due to an SSL error
        if (mSuspended) {
            // wake up the network thread
            restartConnection(false);
        }

        try {
            if (mHttpClientConnection != null && mHttpClientConnection.isOpen()) {
                mHttpClientConnection.close();
            }
        } catch (IOException e) {
            if (HttpLog.LOGV)
                HttpLog.v("HttpsConnection.closeConnection():" +
                          " failed closing connection " + mHost);
            e.printStackTrace();
        }
    }

    /**
     * Restart a secure connection suspended waiting for user interaction.
     */
    void restartConnection(boolean proceed) {
        if (HttpLog.LOGV) {
            HttpLog.v("HttpsConnection.restartConnection():" +
                      " proceed: " + proceed);
        }

        synchronized (mSuspendLock) {
            if (mSuspended) {
                mSuspended = false;
                mAborted = !proceed;
                mSuspendLock.notify();
            }
        }
    }

    @Override
    String getScheme() {
        return "https";
    }
    
    void setSSLClientCertificateFileName(String certfilename){
    	
    }
}

/**
 * Simple exception we throw if the SSL connection is closed by the user.
 *
 * {@hide}
 */
class SSLConnectionClosedByUserException extends SSLException {

    public SSLConnectionClosedByUserException(String reason) {
        super(reason);
    }
}
