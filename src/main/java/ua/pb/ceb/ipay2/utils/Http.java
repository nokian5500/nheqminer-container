package ua.pb.ceb.ipay2.utils;

import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.GZIPInputStream;

import static java.net.HttpURLConnection.*;
import static java.net.Proxy.Type.HTTP;

public class Http {
    public static final String CHARSET_UTF8 = "UTF-8";
    public static final String CONTENT_TYPE_FORM = "application/x-www-form-urlencoded";
    public static final String CONTENT_TYPE_JSON = "application/json";
    public static final String ENCODING_GZIP = "gzip";
    public static final String HEADER_ACCEPT = "Accept";
    public static final String HEADER_ACCEPT_CHARSET = "Accept-Charset";
    public static final String HEADER_ACCEPT_ENCODING = "Accept-Encoding";
    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String HEADER_CACHE_CONTROL = "Cache-Control";
    public static final String HEADER_CONTENT_ENCODING = "Content-Encoding";
    public static final String HEADER_CONTENT_LENGTH = "Content-Length";
    public static final String HEADER_CONTENT_TYPE = "Content-Type";
    public static final String HEADER_DATE = "Date";
    public static final String HEADER_ETAG = "ETag";
    public static final String HEADER_EXPIRES = "Expires";
    public static final String HEADER_IF_NONE_MATCH = "If-None-Match";
    public static final String HEADER_LAST_MODIFIED = "Last-Modified";
    public static final String HEADER_LOCATION = "Location";
    public static final String HEADER_PROXY_AUTHORIZATION = "Proxy-Authorization";
    public static final String HEADER_REFERER = "Referer";
    public static final String HEADER_SERVER = "Server";
    public static final String HEADER_USER_AGENT = "User-Agent";
    public static final String METHOD_DELETE = "DELETE";
    public static final String METHOD_GET = "GET";
    public static final String METHOD_HEAD = "HEAD";
    public static final String METHOD_OPTIONS = "OPTIONS";
    public static final String METHOD_POST = "POST";
    public static final String METHOD_PUT = "PUT";
    public static final String METHOD_TRACE = "TRACE";
    public static final String PARAM_CHARSET = "charset";
    private static final String BOUNDARY = "00content0boundary00";
    private static final String CONTENT_TYPE_MULTIPART = "multipart/form-data; boundary=" + BOUNDARY;
    private static final String CRLF = "\r\n";
    private static final String [] EMPTY_STRINGS = new String [0];
    private static SSLSocketFactory TRUSTED_FACTORY;
    private static HostnameVerifier TRUSTED_VERIFIER;

    private static String getValidCharset(final String charset) {
        if (charset != null && charset.length () > 0) {
            return charset;
        } else {
            return CHARSET_UTF8;
        }
    }

    private static SSLSocketFactory getTrustedFactory() throws HttpRequestException {
        if (TRUSTED_FACTORY == null) {
            final TrustManager [] trustManagers = new TrustManager []{new X509TrustManager () {

                public X509Certificate [] getAcceptedIssuers () {
                    return new X509Certificate[0];
                }

                public void checkClientTrusted (X509Certificate [] chain, String authType) {
                }

                public void checkServerTrusted (X509Certificate [] chain, String authType) {
                }

            }};
            try {
                SSLContext context = SSLContext.getInstance ("TLS");
                context.init (null, trustManagers, new SecureRandom ());
                TRUSTED_FACTORY = context.getSocketFactory ();
            } catch (GeneralSecurityException exception) {
                IOException ioException = new IOException ("Security exception configuring SSL context");
                ioException.initCause (exception);
                throw new HttpRequestException (ioException);
            }
        }
        return TRUSTED_FACTORY;
    }

    private static HostnameVerifier getTrustedVerifier () {
        if (TRUSTED_VERIFIER == null) {
            TRUSTED_VERIFIER = new HostnameVerifier () {

                public boolean verify (String hostname, SSLSession session) {
                    return true;
                }

            };
        }
        return TRUSTED_VERIFIER;
    }

    private static StringBuilder addPathSeparator (final String baseUrl, final StringBuilder result) {
        if (baseUrl.indexOf (':') + 2 == baseUrl.lastIndexOf ('/')) {
            result.append ('/');
        }
        return result;
    }

    private static StringBuilder addParamPrefix (final String baseUrl, final StringBuilder result) {
        final int queryStart = baseUrl.indexOf ('?');
        final int lastChar = result.length () - 1;
        if (queryStart == -1) {
            result.append ('?');
        } else if (queryStart < lastChar && baseUrl.charAt (lastChar) != '&') {
            result.append ('&');
        }
        return result;
    }

    public interface ConnectionFactory {
        HttpURLConnection create(URL url) throws IOException;
        HttpURLConnection create(URL url, Proxy proxy) throws IOException;

        ConnectionFactory DEFAULT = new ConnectionFactory () {

            public HttpURLConnection create (URL url) throws IOException {
                return (HttpURLConnection) url.openConnection ();
            }

            public HttpURLConnection create (URL url, Proxy proxy) throws IOException {
                return (HttpURLConnection) url.openConnection (proxy);
            }

        };

    }

    private static ConnectionFactory CONNECTION_FACTORY = ConnectionFactory.DEFAULT;

    public static void setConnectionFactory (final ConnectionFactory connectionFactory) {
        if (connectionFactory == null) {
            CONNECTION_FACTORY = ConnectionFactory.DEFAULT;
        } else {
            CONNECTION_FACTORY = connectionFactory;
        }
    }

    public interface UploadProgress {
        void onUpload(long uploaded, long total);

        UploadProgress DEFAULT = new UploadProgress () {

            public void onUpload(long uploaded, long total) {
            }

        };
    }

    public static class Base64 {
        private final static byte EQUALS_SIGN = (byte) '=';
        private final static String PREFERRED_ENCODING = "US-ASCII";
        private final static byte[] _STANDARD_ALPHABET = {(byte) 'A', (byte) 'B',
                (byte) 'C', (byte) 'D', (byte) 'E', (byte) 'F', (byte) 'G', (byte) 'H',
                (byte) 'I', (byte) 'J', (byte) 'K', (byte) 'L', (byte) 'M', (byte) 'N',
                (byte) 'O', (byte) 'P', (byte) 'Q', (byte) 'R', (byte) 'S', (byte) 'T',
                (byte) 'U', (byte) 'V', (byte) 'W', (byte) 'X', (byte) 'Y', (byte) 'Z',
                (byte) 'a', (byte) 'b', (byte) 'c', (byte) 'd', (byte) 'e', (byte) 'f',
                (byte) 'g', (byte) 'h', (byte) 'i', (byte) 'j', (byte) 'k', (byte) 'l',
                (byte) 'm', (byte) 'n', (byte) 'o', (byte) 'p', (byte) 'q', (byte) 'r',
                (byte) 's', (byte) 't', (byte) 'u', (byte) 'v', (byte) 'w', (byte) 'x',
                (byte) 'y', (byte) 'z', (byte) '0', (byte) '1', (byte) '2', (byte) '3',
                (byte) '4', (byte) '5', (byte) '6', (byte) '7', (byte) '8', (byte) '9',
                (byte) '+', (byte) '/'};

        private Base64 () {
        }

        private static byte [] encode3to4 (byte [] source, int srcOffset, int numSigBytes, byte [] destination, int destOffset) {
            byte [] ALPHABET = _STANDARD_ALPHABET;
            int inBuff = (numSigBytes > 0 ? ((source[srcOffset] << 24) >>> 8) : 0) | (numSigBytes > 1 ? ((source[srcOffset + 1] << 24) >>> 16) : 0) | (numSigBytes > 2 ? ((source[srcOffset + 2] << 24) >>> 24) : 0);
            switch (numSigBytes) {
                case 3:
                    destination [destOffset] = ALPHABET [(inBuff >>> 18)];
                    destination [destOffset + 1] = ALPHABET [(inBuff >>> 12) & 0x3f];
                    destination [destOffset + 2] = ALPHABET [(inBuff >>> 6) & 0x3f];
                    destination [destOffset + 3] = ALPHABET [(inBuff) & 0x3f];
                return destination;

                case 2:
                    destination [destOffset] = ALPHABET [(inBuff >>> 18)];
                    destination [destOffset + 1] = ALPHABET [(inBuff >>> 12) & 0x3f];
                    destination [destOffset + 2] = ALPHABET [(inBuff >>> 6) & 0x3f];
                    destination [destOffset + 3] = EQUALS_SIGN;
                return destination;

                case 1:
                    destination [destOffset] = ALPHABET [(inBuff >>> 18)];
                    destination [destOffset + 1] = ALPHABET [(inBuff >>> 12) & 0x3f];
                    destination [destOffset + 2] = EQUALS_SIGN;
                    destination [destOffset + 3] = EQUALS_SIGN;
                return destination;

                default:
                    return destination;
            }
        }

        public static String encode (String string) {
            byte [] bytes;
            try {
                bytes = string.getBytes (PREFERRED_ENCODING);
            } catch (UnsupportedEncodingException exception) {
                bytes = string.getBytes ();
            }
            return encodeBytes (bytes);
        }

        public static String encodeBytes (byte [] source) {
            return encodeBytes (source, 0, source.length);
        }

        public static String encodeBytes (byte [] source, int off, int len) {
            byte [] encoded = encodeBytesToBytes (source, off, len);
            try {
                return new String (encoded, PREFERRED_ENCODING);
            } catch (UnsupportedEncodingException exception) {
                return new String (encoded);
            }
        }

        public static byte [] encodeBytesToBytes (byte [] source, int off, int len) {
            if (source == null) {
                throw new NullPointerException ("Cannot serialize a null array.");
            }
            if (off < 0) {
                throw new IllegalArgumentException ("Cannot have negative offset: " + off);
            }
            if (len < 0) {
                throw new IllegalArgumentException ("Cannot have length offset: " + len);
            }
            if (off + len > source.length) {
                throw new IllegalArgumentException (String.format ("Cannot have offset of %d and length of %d with array of length %d", off, len, source.length));
            }
            int encLen = (len / 3) * 4 + (len % 3 > 0 ? 4 : 0);
            byte [] outBuff = new byte [encLen];
            int d = 0;
            int e = 0;
            int len2 = len - 2;
            for ( ; d < len2 ; d += 3, e += 4) {
                encode3to4 (source, d + off, 3, outBuff, e);
            }
            if (d < len) {
                encode3to4 (source, d + off, len - d, outBuff, e);
                e += 4;
            }
            if (e <= outBuff.length - 1) {
                byte [] finalOut = new byte [e];
                System.arraycopy (outBuff, 0, finalOut, 0, e);
                return finalOut;
            } else {
                return outBuff;
            }
        }
    }

    public static class HttpRequestException extends RuntimeException {
        private static final long serialVersionUID = -1170466989781746231L;

        public HttpRequestException (final IOException cause) {
            super (cause);
        }

        @Override
        public IOException getCause () {
            return (IOException) super.getCause ();
        }

    }

    protected static abstract class Operation <V> implements Callable <V> {
        protected abstract V run () throws HttpRequestException, IOException;
        protected abstract void done () throws IOException;

        public V call () throws HttpRequestException {
            boolean thrown = false;
            try {
                return run ();
            } catch (HttpRequestException exception) {
                thrown = true;
                throw exception;
            } catch (IOException exception) {
                thrown = true;
                throw new HttpRequestException (exception);
            } finally {
                try {
                    done ();
                } catch (IOException exception) {
                    if (!thrown) {
                        throw new HttpRequestException(exception);
                    }
                }
            }
        }
    }

    protected static abstract class CloseOperation <V> extends Operation <V> {
        private final Closeable closeable;
        private final boolean ignoreCloseExceptions;

        protected CloseOperation (final Closeable closeable, final boolean ignoreCloseExceptions) {
            this.closeable = closeable;
            this.ignoreCloseExceptions = ignoreCloseExceptions;
        }

        @Override
        protected void done () throws IOException {
            if (closeable instanceof Flushable) {
                ((Flushable) closeable).flush ();
            }
            if (ignoreCloseExceptions) {
                try {
                    closeable.close ();
                } catch (IOException exception) {
                }
            } else {
                closeable.close ();
            }
        }
    }

    protected static abstract class FlushOperation <V> extends Operation <V> {
        private final Flushable flushable;

        protected FlushOperation (final Flushable flushable) {
            this.flushable = flushable;
        }

        @Override
        protected void done () throws IOException {
            flushable.flush ();
        }
    }

    public static class RequestOutputStream extends BufferedOutputStream {
        private final CharsetEncoder encoder;

        public RequestOutputStream (final OutputStream stream, final String charset, final int bufferSize) {
            super (stream, bufferSize);
            encoder = Charset.forName (getValidCharset (charset)).newEncoder ();
        }

        public RequestOutputStream write (final String value) throws IOException {
            final ByteBuffer bytes = encoder.encode (CharBuffer.wrap (value));
            super.write (bytes.array (), 0, bytes.limit ());
            return this;
        }
    }

    public static String encode (final CharSequence url) throws HttpRequestException {
        URL parsed;
        try {
            parsed = new URL (url.toString ());
        } catch (IOException exception) {
            throw new HttpRequestException (exception);
        }
        String host = parsed.getHost ();
        int port = parsed.getPort ();
        if (port != -1) {
            host = host + ':' + Integer.toString (port);
        }
        try {
            String encoded = new URI (parsed.getProtocol (), host, parsed.getPath (), parsed.getQuery (), null).toASCIIString ();
            int paramsStart = encoded.indexOf ('?');
            if (paramsStart > 0 && paramsStart + 1 < encoded.length ()) {
                encoded = encoded.substring (0, paramsStart + 1) + encoded.substring (paramsStart + 1).replace ("+", "%2B");
            }
            return encoded;
        } catch (URISyntaxException exception) {
            IOException ioException = new IOException ("Parsing URI failed");
            ioException.initCause (exception);
            throw new HttpRequestException (ioException);
        }
    }

    public static String append (final CharSequence url, final Map <?, ?> params) {
        final String baseUrl = url.toString ();
        if (params == null || params.isEmpty ()) {
            return baseUrl;
        }
        final StringBuilder result = new StringBuilder (baseUrl);
        addPathSeparator (baseUrl, result);
        addParamPrefix (baseUrl, result);
        Entry <?, ?> entry;
        Object value;
        Iterator <?> iterator = params.entrySet ().iterator ();
        entry = (Entry <?, ?>) iterator.next ();
        result.append (entry.getKey ().toString ());
        result.append ('=');
        value = entry.getValue ();
        if (value != null) {
            result.append (value);
        }
        while (iterator.hasNext ()) {
            result.append ('&');
            entry = (Entry <?, ?>) iterator.next ();
            result.append (entry.getKey ().toString ());
            result.append ('=');
            value = entry.getValue ();
            if (value != null) {
                result.append (value);
            }
        }
        return result.toString ();
    }

    public static String append (final CharSequence url, final Object ... params) {
        final String baseUrl = url.toString ();
        if (params == null || params.length == 0) {
            return baseUrl;
        }
        if (params.length % 2 != 0) {
            throw new IllegalArgumentException ("Must specify an even number of parameter names/values");
        }
        final StringBuilder result = new StringBuilder (baseUrl);
        addPathSeparator (baseUrl, result);
        addParamPrefix (baseUrl, result);
        Object value;
        result.append (params[0]);
        result.append ('=');
        value = params [1];
        if (value != null) {
            result.append (value);
        }
        for (int i = 2 ; i < params.length ; i += 2) {
            result.append ('&');
            result.append (params[i]);
            result.append ('=');
            value = params[i + 1];
            if (value != null) {
                result.append (value);
            }
        }
        return result.toString ();
    }

    public static Http get (final CharSequence url) throws HttpRequestException {
        return new Http (url, METHOD_GET);
    }

    public static Http get (final URL url) throws HttpRequestException {
        return new Http (url, METHOD_GET);
    }

    public static Http get (final CharSequence baseUrl, final Map <?, ?> params, final boolean encode) {
        String url = append (baseUrl, params);
        return get (encode ? encode (url) : url);
    }

    public static Http get (final CharSequence baseUrl, final boolean encode, final Object ... params) {
        String url = append (baseUrl, params);
        return get (encode ? encode (url) : url);
    }

    public static Http post (final CharSequence url) throws HttpRequestException {
        return new Http (url, METHOD_POST);
    }

    public static Http post (final URL url) throws HttpRequestException {
        return new Http (url, METHOD_POST);
    }

    public static Http post (final CharSequence baseUrl, final Map <?, ?> params, final boolean encode) {
        String url = append (baseUrl, params);
        return post (encode ? encode (url) : url);
    }

    public static Http post (final CharSequence baseUrl, final boolean encode, final Object ... params) {
        String url = append (baseUrl, params);
        return post (encode ? encode (url) : url);
    }

    public static Http put (final CharSequence url) throws HttpRequestException {
        return new Http (url, METHOD_PUT);
    }

    public static Http put (final URL url) throws HttpRequestException {
        return new Http (url, METHOD_PUT);
    }

    public static Http put (final CharSequence baseUrl, final Map <?, ?> params, final boolean encode) {
        String url = append (baseUrl, params);
        return put (encode ? encode (url) : url);
    }

    public static Http put (final CharSequence baseUrl, final boolean encode, final Object ... params) {
        String url = append (baseUrl, params);
        return put (encode ? encode (url) : url);
    }

    public static Http delete (final CharSequence url) throws HttpRequestException {
        return new Http (url, METHOD_DELETE);
    }

    public static Http delete (final URL url) throws HttpRequestException {
        return new Http (url, METHOD_DELETE);
    }

    public static Http delete (final CharSequence baseUrl, final Map <?, ?> params, final boolean encode) {
        String url = append (baseUrl, params);
        return delete (encode ? encode (url) : url);
    }

    public static Http delete (final CharSequence baseUrl, final boolean encode, final Object ... params) {
        String url = append (baseUrl, params);
        return delete (encode ? encode (url) : url);
    }

    public static Http head (final CharSequence url) throws HttpRequestException {
        return new Http (url, METHOD_HEAD);
    }

    public static Http head (final URL url) throws HttpRequestException {
        return new Http (url, METHOD_HEAD);
    }

    public static Http head (final CharSequence baseUrl, final Map <?, ?> params, final boolean encode) {
        String url = append (baseUrl, params);
        return head (encode ? encode (url) : url);
    }

    public static Http head (final CharSequence baseUrl, final boolean encode, final Object ... params) {
        String url = append (baseUrl, params);
        return head (encode ? encode (url) : url);
    }

    public static Http options (final CharSequence url) throws HttpRequestException {
        return new Http (url, METHOD_OPTIONS);
    }

    public static Http options (final URL url) throws HttpRequestException {
        return new Http (url, METHOD_OPTIONS);
    }

    public static Http trace (final CharSequence url) throws HttpRequestException {
        return new Http (url, METHOD_TRACE);
    }

    public static Http trace (final URL url) throws HttpRequestException {
        return new Http (url, METHOD_TRACE);
    }

    public static void keepAlive (final boolean keepAlive) {
        setProperty ("http.keepAlive", Boolean.toString (keepAlive));
    }

    public static void maxConnections (final int maxConnections) {
        setProperty ("http.maxConnections", Integer.toString (maxConnections));
    }

    public static void proxyHost (final String host) {
        setProperty ("http.proxyHost", host);
        setProperty ("https.proxyHost", host);
    }

    public static void proxyPort (final int port) {
        final String portValue = Integer.toString (port);
        setProperty ("http.proxyPort", portValue);
        setProperty ("https.proxyPort", portValue);
    }

    public static void nonProxyHosts (final String ... hosts) {
        if (hosts != null && hosts.length > 0) {
            StringBuilder separated = new StringBuilder ();
            int last = hosts.length - 1;
            for (int i = 0 ; i < last ; i++) {
                separated.append (hosts [i]).append ('|');
            }
            separated.append (hosts [last]);
            setProperty ("http.nonProxyHosts", separated.toString ());
        } else {
            setProperty ("http.nonProxyHosts", null);
        }
    }

    private static String setProperty (final String name, final String value) {
        final PrivilegedAction <String> action;
        if (value != null) {
            action = new PrivilegedAction <String> () {

                public String run () {
                    return System.setProperty (name, value);
                }
            };
        } else
            action = new PrivilegedAction <String> () {

                public String run () {
                    return System.clearProperty (name);
                }

            };
        return AccessController.doPrivileged (action);
    }

    private HttpURLConnection connection = null;
    private final URL url;
    private final String requestMethod;
    private RequestOutputStream output;
    private boolean multipart;
    private boolean form;
    private boolean ignoreCloseExceptions = true;
    private boolean uncompress = false;
    private int bufferSize = 8192;
    private long totalSize = -1;
    private long totalWritten = 0;
    private String httpProxyHost;
    private int httpProxyPort;
    private UploadProgress progress = UploadProgress.DEFAULT;

    public Http (final CharSequence url, final String method) throws HttpRequestException {
        try {
            this.url = new URL (url.toString ());
        } catch (MalformedURLException exception) {
            throw new HttpRequestException (exception);
        }
        this.requestMethod = method;
    }

    public Http (final URL url, final String method) throws HttpRequestException {
        this.url = url;
        this.requestMethod = method;
    }

    private Proxy createProxy () {
        return new Proxy (HTTP, new InetSocketAddress (httpProxyHost, httpProxyPort));
    }

    private HttpURLConnection createConnection () {
        try {
            final HttpURLConnection connection;
            if (httpProxyHost != null) {
                connection = CONNECTION_FACTORY.create (url, createProxy ());
            } else {
                connection = CONNECTION_FACTORY.create (url);
            }
            connection.setRequestMethod (requestMethod);
            return connection;
        } catch (IOException exception) {
            throw new HttpRequestException (exception);
        }
    }

    @Override
    public String toString () {
        return method () + ' ' + url ();
    }

    public HttpURLConnection getConnection () {
        if (connection == null) {
            connection = createConnection ();
        }
        return connection;
    }

    public Http ignoreCloseExceptions (final boolean ignore) {
        ignoreCloseExceptions = ignore;
        return this;
    }

    public boolean ignoreCloseExceptions () {
        return ignoreCloseExceptions;
    }

    public int code () throws HttpRequestException {
        try {
            closeOutput ();
            return getConnection ().getResponseCode ();
        } catch (IOException exception) {
            throw new HttpRequestException (exception);
        }
    }

    public Http code (final AtomicInteger output) throws HttpRequestException {
        output.set (code ());
        return this;
    }

    public boolean ok () throws HttpRequestException {
        return HTTP_OK == code ();
    }

    public boolean created () throws HttpRequestException {
        return HTTP_CREATED == code ();
    }

    public boolean noContent () throws HttpRequestException {
        return HTTP_NO_CONTENT == code ();
    }

    public boolean serverError () throws HttpRequestException {
        return HTTP_INTERNAL_ERROR == code ();
    }

    public boolean badRequest () throws HttpRequestException {
        return HTTP_BAD_REQUEST == code ();
    }

    public boolean notFound () throws HttpRequestException {
        return HTTP_NOT_FOUND == code ();
    }

    public boolean notModified () throws HttpRequestException {
        return HTTP_NOT_MODIFIED == code ();
    }

    public String message () throws HttpRequestException {
        try {
            closeOutput ();
            return getConnection ().getResponseMessage ();
        } catch (IOException exception) {
            throw new HttpRequestException (exception);
        }
    }

    public Http disconnect () {
        getConnection ().disconnect ();
        return this;
    }

    public Http chunk (final int size) {
        getConnection ().setChunkedStreamingMode (size);
        return this;
    }

    public Http bufferSize (final int size) {
        if (size < 1) {
            throw new IllegalArgumentException ("Size must be greater than zero");
        }
        bufferSize = size;
        return this;
    }

    public int bufferSize () {
        return bufferSize;
    }

    public Http uncompress (final boolean uncompress) {
        this.uncompress = uncompress;
        return this;
    }

    protected ByteArrayOutputStream byteStream () {
        final int size = contentLength ();
        if (size > 0) {
            return new ByteArrayOutputStream (size);
        } else {
            return new ByteArrayOutputStream ();
        }
    }

    public String body (final String charset) throws HttpRequestException {
        final ByteArrayOutputStream output = byteStream ();
        try {
            copy (buffer (), output);
            return output.toString (getValidCharset (charset));
        } catch (IOException exception) {
            throw new HttpRequestException (exception);
        }
    }

    public String body () throws HttpRequestException {
        return body (charset ());
    }

    public Http body (final AtomicReference <String> output) throws HttpRequestException {
        output.set (body ());
        return this;
    }

    public Http body (final AtomicReference <String> output, final String charset) throws HttpRequestException {
        output.set (body (charset));
        return this;
    }

    public boolean isBodyEmpty () throws HttpRequestException {
        return contentLength () == 0;
    }

    public byte[] bytes () throws HttpRequestException {
        final ByteArrayOutputStream output = byteStream ();
        try {
            copy (buffer (), output);
        } catch (IOException exception) {
            throw new HttpRequestException (exception);
        }
        return output.toByteArray ();
    }

    public BufferedInputStream buffer () throws HttpRequestException {
        return new BufferedInputStream (stream (), bufferSize);
    }

    public InputStream stream () throws HttpRequestException {
        InputStream stream;
        if (code () < HTTP_BAD_REQUEST) {
            try {
                stream = getConnection ().getInputStream ();
            } catch (IOException exception) {
                throw new HttpRequestException (exception);
            }
        } else {
            stream = getConnection ().getErrorStream ();
            if (stream == null) {
                try {
                    stream = getConnection ().getInputStream ();
                } catch (IOException exception) {
                    if (contentLength () > 0) {
                        throw new HttpRequestException (exception);
                    } else {
                        stream = new ByteArrayInputStream (new byte[0]);
                    }
                }
            }
        }
        if (!uncompress || !ENCODING_GZIP.equals (contentEncoding ())) {
            return stream;
        } else {
            try {
                return new GZIPInputStream(stream);
            } catch (IOException exception) {
                throw new HttpRequestException (exception);
            }
        }
    }

    public InputStreamReader reader (final String charset) throws HttpRequestException {
        try {
            return new InputStreamReader (stream (), getValidCharset (charset));
        } catch (UnsupportedEncodingException exception) {
            throw new HttpRequestException (exception);
        }
    }

    public InputStreamReader reader () throws HttpRequestException {
        return reader (charset ());
    }

    public BufferedReader bufferedReader (final String charset) throws HttpRequestException {
        return new BufferedReader (reader (charset), bufferSize);
    }

    public BufferedReader bufferedReader () throws HttpRequestException {
        return bufferedReader (charset ());
    }

    public Http receive (final File file) throws HttpRequestException {
        final OutputStream output;
        try {
            output = new BufferedOutputStream (new FileOutputStream (file), bufferSize);
        } catch (FileNotFoundException exception) {
            throw new HttpRequestException (exception);
        }
        return new CloseOperation <Http> (output, ignoreCloseExceptions) {

            @Override
            protected Http run () throws HttpRequestException, IOException {
                return receive (output);
            }

        }.call ();
    }

    public Http receive (final OutputStream output) throws HttpRequestException {
        try {
            return copy (buffer (), output);
        } catch (IOException exception) {
            throw new HttpRequestException (exception);
        }
    }

    public Http receive (final PrintStream output) throws HttpRequestException {
        return receive ((OutputStream) output);
    }

    public Http receive (final Appendable appendable) throws HttpRequestException {
        final BufferedReader reader = bufferedReader ();
        return new CloseOperation <Http> (reader, ignoreCloseExceptions) {

            @Override
            public Http run () throws IOException {
                final CharBuffer buffer = CharBuffer.allocate (bufferSize);
                int read;
                while ((read = reader.read (buffer)) != -1) {
                    buffer.rewind ();
                    appendable.append (buffer, 0, read);
                    buffer.rewind ();
                }
                return Http.this;
            }
        }.call ();
    }

    public Http receive (final Writer writer) throws HttpRequestException {
        final BufferedReader reader = bufferedReader ();
        return new CloseOperation <Http> (reader, ignoreCloseExceptions) {

            @Override
            public Http run () throws IOException {
                return copy (reader, writer);
            }

        }.call ();
    }

    public Http readTimeout (final int timeout) {
        getConnection ().setReadTimeout (timeout);
        return this;
    }

    public Http connectTimeout (final int timeout) {
        getConnection ().setConnectTimeout (timeout);
        return this;
    }

    public Http header (final String name, final String value) {
        getConnection ().setRequestProperty (name, value);
        return this;
    }

    public Http header (final String name, final Number value) {
        return header (name, value != null ? value.toString() : null);
    }

    public Http headers (final Map<String, String> headers) {
        if (!headers.isEmpty ()) {
            for (Entry <String, String> header : headers.entrySet ()) {
                header (header);
            }
        }
        return this;
    }

    public Http header (final Entry<String, String> header) {
        return header (header.getKey (), header.getValue ());
    }

    public String header (final String name) throws HttpRequestException {
        closeOutputQuietly ();
        return getConnection ().getHeaderField (name);
    }

    public Map <String, List <String>> headers () throws HttpRequestException {
        closeOutputQuietly ();
        return getConnection ().getHeaderFields ();
    }

    public long dateHeader (final String name) throws HttpRequestException {
        return dateHeader (name, -1L);
    }

    public long dateHeader (final String name, final long defaultValue) throws HttpRequestException {
        closeOutputQuietly ();
        return getConnection ().getHeaderFieldDate (name, defaultValue);
    }

    public int intHeader (final String name) throws HttpRequestException {
        return intHeader (name, -1);
    }

    public int intHeader (final String name, final int defaultValue) throws HttpRequestException {
        closeOutputQuietly ();
        return getConnection ().getHeaderFieldInt (name, defaultValue);
    }

    public String [] headers (final String name) {
        final Map <String, List <String>> headers = headers ();
        if (headers == null || headers.isEmpty ()) {
            return EMPTY_STRINGS;
        }
        final List <String> values = headers.get (name);
        if (values != null && !values.isEmpty ()) {
            return values.toArray (new String [values.size ()]);
        } else {
            return EMPTY_STRINGS;
        }
    }

    public String parameter (final String headerName, final String paramName) {
        return getParam (header (headerName), paramName);
    }

    public Map <String, String> parameters (final String headerName) {
        return getParams (header (headerName));
    }

    protected Map <String, String> getParams (final String header) {
        if (header == null || header.length () == 0) {
            return Collections.emptyMap ();
        }
        final int headerLength = header.length ();
        int start = header.indexOf (';') + 1;
        if (start == 0 || start == headerLength) {
            return Collections.emptyMap ();
        }
        int end = header.indexOf (';', start);
        if (end == -1) {
            end = headerLength;
        }
        Map <String, String> params = new LinkedHashMap <String, String> ();
        while (start < end) {
            int nameEnd = header.indexOf ('=', start);
            if (nameEnd != -1 && nameEnd < end) {
                String name = header.substring (start, nameEnd).trim ();
                if (name.length () > 0) {
                    String value = header.substring (nameEnd + 1, end).trim ();
                    int length = value.length ();
                    if (length != 0) {
                        if (length > 2 && '"' == value.charAt (0) && '"' == value.charAt (length - 1)) {
                            params.put (name, value.substring (1, length - 1));
                        } else{
                            params.put (name, value);
                        }
                    }
                }
            }
            start = end + 1;
            end = header.indexOf (';', start);
            if (end == -1) {
                end = headerLength;
            }
        }
        return params;
    }

    protected String getParam (final String value, final String paramName) {
        if (value == null || value.length() == 0) {
            return null;
        }
        final int length = value.length ();
        int start = value.indexOf (';') + 1;
        if (start == 0 || start == length) {
            return null;
        }
        int end = value.indexOf (';', start);
        if (end == -1) {
            end = length;
        }
        while (start < end) {
            int nameEnd = value.indexOf ('=', start);
            if (nameEnd != -1 && nameEnd < end && paramName.equals (value.substring (start, nameEnd).trim ())) {
                String paramValue = value.substring (nameEnd + 1, end).trim ();
                int valueLength = paramValue.length ();
                if (valueLength != 0) {
                    if (valueLength > 2 && '"' == paramValue.charAt (0) && '"' == paramValue.charAt (valueLength - 1)) {
                        return paramValue.substring (1, valueLength - 1);
                    } else {
                        return paramValue;
                    }
                }
            }
            start = end + 1;
            end = value.indexOf (';', start);
            if (end == -1) {
                end = length;
            }
        }
        return null;
    }

    public String charset () {
        return parameter (HEADER_CONTENT_TYPE, PARAM_CHARSET);
    }

    public Http userAgent (final String userAgent) {
        return header (HEADER_USER_AGENT, userAgent);
    }

    public Http referer (final String referer) {
        return header (HEADER_REFERER, referer);
    }

    public Http useCaches (final boolean useCaches) {
        getConnection ().setUseCaches (useCaches);
        return this;
    }

    public Http acceptEncoding (final String acceptEncoding) {
        return header (HEADER_ACCEPT_ENCODING, acceptEncoding);
    }

    public Http acceptGzipEncoding () {
        return acceptEncoding (ENCODING_GZIP);
    }

    public Http acceptCharset (final String acceptCharset) {
        return header (HEADER_ACCEPT_CHARSET, acceptCharset);
    }

    public String contentEncoding () {
        return header (HEADER_CONTENT_ENCODING);
    }

    public String server () {
        return header (HEADER_SERVER);
    }

    public long date () {
        return dateHeader (HEADER_DATE);
    }

    public String cacheControl () {
        return header (HEADER_CACHE_CONTROL);
    }

    public String eTag () {
        return header (HEADER_ETAG);
    }

    public long expires () {
        return dateHeader (HEADER_EXPIRES);
    }

    public long lastModified () {
        return dateHeader (HEADER_LAST_MODIFIED);
    }

    public String location () {
        return header (HEADER_LOCATION);
    }

    public Http authorization (final String authorization) {
        return header (HEADER_AUTHORIZATION, authorization);
    }

    public Http proxyAuthorization (final String proxyAuthorization) {
        return header (HEADER_PROXY_AUTHORIZATION, proxyAuthorization);
    }

    public Http basic (final String name, final String password) {
        return authorization ("Basic " + Base64.encode(name + ':' + password));
    }

    public Http proxyBasic (final String name, final String password) {
        return proxyAuthorization ("Basic " + Base64.encode(name + ':' + password));
    }

    public Http ifModifiedSince (final long ifModifiedSince) {
        getConnection ().setIfModifiedSince (ifModifiedSince);
        return this;
    }

    public Http ifNoneMatch (final String ifNoneMatch) {
        return header (HEADER_IF_NONE_MATCH, ifNoneMatch);
    }

    public Http contentType (final String contentType) {
        return contentType (contentType, null);
    }

    public Http contentType (final String contentType, final String charset) {
        if (charset != null && charset.length () > 0) {
            final String separator = "; " + PARAM_CHARSET + '=';
            return header (HEADER_CONTENT_TYPE, contentType + separator + charset);
        } else {
            return header (HEADER_CONTENT_TYPE, contentType);
        }
    }

    public String contentType () {
        return header (HEADER_CONTENT_TYPE);
    }

    public int contentLength () {
        return intHeader (HEADER_CONTENT_LENGTH);
    }

    public Http contentLength (final String contentLength) {
        return contentLength (Integer.parseInt (contentLength));
    }

    public Http contentLength (final int contentLength) {
        getConnection ().setFixedLengthStreamingMode (contentLength);
        return this;
    }

    public Http accept (final String accept) {
        return header (HEADER_ACCEPT, accept);
    }

    public Http acceptJson () {
        return accept(CONTENT_TYPE_JSON);
    }

    protected Http copy (final InputStream input, final OutputStream output) throws IOException {
        return new CloseOperation <Http> (input, ignoreCloseExceptions) {

            @Override
            public Http run () throws IOException {
                final byte [] buffer = new byte [bufferSize];
                int read;
                while ((read = input.read (buffer)) != -1) {
                    output.write (buffer, 0, read);
                    totalWritten += read;
                    progress.onUpload (totalWritten, totalSize);
                }
                return Http.this;
            }

        }.call ();
    }

    protected Http copy (final Reader input, final Writer output) throws IOException {
        return new CloseOperation <Http> (input, ignoreCloseExceptions) {

            @Override
            public Http run () throws IOException {
                final char [] buffer = new char [bufferSize];
                int read;
                while ((read = input.read (buffer)) != -1) {
                    output.write (buffer, 0, read);
                    totalWritten += read;
                    progress.onUpload (totalWritten, -1);
                }
                return Http.this;
            }

        }.call ();
    }

    public Http progress (final UploadProgress callback) {
        if (callback == null) {
            progress = UploadProgress.DEFAULT;
        } else {
            progress = callback;
        }
        return this;
    }

    private Http incrementTotalSize (final long size) {
        if (totalSize == -1) {
            totalSize = 0;
        }
        totalSize += size;
        return this;
    }

    protected Http closeOutput () throws IOException {
        progress (null);
        if (output == null) {
            return this;
        }
        if (multipart) {
            output.write (CRLF + "--" + BOUNDARY + "--" + CRLF);
        }
        if (ignoreCloseExceptions) {
            try {
                output.close ();
            } catch (IOException ignored) {
            }
        } else {
            output.close ();
        }
        output = null;
        return this;
    }

    protected Http closeOutputQuietly () throws HttpRequestException {
        try {
            return closeOutput ();
        } catch (IOException exception) {
            throw new HttpRequestException (exception);
        }
    }

    protected Http openOutput () throws IOException {
        if (output != null) {
            return this;
        }
        getConnection ().setDoOutput (true);
        final String charset = getParam (getConnection ().getRequestProperty (HEADER_CONTENT_TYPE), PARAM_CHARSET);
        output = new RequestOutputStream (getConnection ().getOutputStream (), charset, bufferSize);
        return this;
    }

    protected Http startPart () throws IOException {
        if (!multipart) {
            multipart = true;
            contentType (CONTENT_TYPE_MULTIPART).openOutput ();
            output.write ("--" + BOUNDARY + CRLF);
        } else {
            output.write (CRLF + "--" + BOUNDARY + CRLF);
        }
        return this;
    }

    protected Http writePartHeader (final String name, final String filename) throws IOException {
        return writePartHeader (name, filename, null);
    }

    protected Http writePartHeader (final String name, final String filename, final String contentType) throws IOException {
        final StringBuilder partBuffer = new StringBuilder ();
        partBuffer.append ("form-data; name=\"").append (name);
        if (filename != null) {
            partBuffer.append ("\"; filename=\"").append (filename);
        }
        partBuffer.append ('"');
        partHeader ("Content-Disposition", partBuffer.toString ());
        if (contentType != null) {
            partHeader (HEADER_CONTENT_TYPE, contentType);
        }
        return send (CRLF);
    }

    public Http part (final String name, final String part) {
        return part (name, null, part);
    }

    public Http part (final String name, final String filename, final String part) throws HttpRequestException {
        return part (name, filename, null, part);
    }

    public Http part (final String name, final String filename, final String contentType, final String part) throws HttpRequestException {
        try {
            startPart ();
            writePartHeader (name, filename, contentType);
            output.write (part);
        } catch (IOException exception) {
            throw new HttpRequestException (exception);
        }
        return this;
    }

    public Http part (final String name, final Number part) throws HttpRequestException {
        return part (name, null, part);
    }

    public Http part (final String name, final String filename, final Number part) throws HttpRequestException {
        return part (name, filename, part != null ? part.toString () : null);
    }

    public Http part (final String name, final File part) throws HttpRequestException {
        return part (name, null, part);
    }

    public Http part (final String name, final String filename, final File part) throws HttpRequestException {
        return part (name, filename, null, part);
    }

    public Http part (final String name, final String filename, final String contentType, final File part) throws HttpRequestException {
        final InputStream stream;
        try {
            stream = new BufferedInputStream (new FileInputStream (part));
            incrementTotalSize (part.length ());
        } catch (IOException exception) {
            throw new HttpRequestException (exception);
        }
        return part (name, filename, contentType, stream);
    }

    public Http part (final String name, final InputStream part) throws HttpRequestException {
        return part (name, null, null, part);
    }

    public Http part (final String name, final String filename, final String contentType, final InputStream part) throws HttpRequestException {
        try {
            startPart ();
            writePartHeader (name, filename, contentType);
            copy (part, output);
        } catch (IOException exception) {
            throw new HttpRequestException (exception);
        }
        return this;
    }

    public Http partHeader (final String name, final String value) throws HttpRequestException {
        return send (name).send (": ").send (value).send (CRLF);
    }

    public Http send (final File input) throws HttpRequestException {
        final InputStream stream;
        try {
            stream = new BufferedInputStream (new FileInputStream (input));
            incrementTotalSize (input.length ());
        } catch (FileNotFoundException exception) {
            throw new HttpRequestException (exception);
        }
        return send (stream);
    }

    public Http send (final byte[] input) throws HttpRequestException {
        if (input != null) {
            incrementTotalSize (input.length);
        }
        return send (new ByteArrayInputStream (input));
    }

    public Http send (final InputStream input) throws HttpRequestException {
        try {
            openOutput ();
            copy (input, output);
        } catch (IOException exception) {
            throw new HttpRequestException (exception);
        }
        return this;
    }

    public Http send (final Reader input) throws HttpRequestException {
        try {
            openOutput ();
        } catch (IOException exception) {
            throw new HttpRequestException (exception);
        }
        final Writer writer = new OutputStreamWriter (output, output.encoder.charset ());
        return new FlushOperation <Http> (writer) {

            @Override
            protected Http run () throws IOException {
                return copy (input, writer);
            }

        }.call ();
    }

    public Http send (final CharSequence value) throws HttpRequestException {
        try {
            openOutput ();
            output.write (value.toString ());
        } catch (IOException exception) {
            throw new HttpRequestException (exception);
        }
        return this;
    }

    public OutputStreamWriter writer () throws HttpRequestException {
        try {
            openOutput ();
            return new OutputStreamWriter (output, output.encoder.charset ());
        } catch (IOException exception) {
            throw new HttpRequestException (exception);
        }
    }

    public Http form (final Map <?, ?> values) throws HttpRequestException {
        return form (values, CHARSET_UTF8);
    }

    public Http form (final Entry <?, ?> entry) throws HttpRequestException {
        return form (entry, CHARSET_UTF8);
    }

    public Http form (final Entry <?, ?> entry, final String charset) throws HttpRequestException {
        return form (entry.getKey (), entry.getValue (), charset);
    }

    public Http form (final Object name, final Object value) throws HttpRequestException {
        return form (name, value, CHARSET_UTF8);
    }

    public Http form (final Object name, final Object value, String charset) throws HttpRequestException {
        final boolean first = !form;
        if (first) {
            contentType (CONTENT_TYPE_FORM, charset);
            form = true;
        }
        charset = getValidCharset (charset);
        try {
            openOutput ();
            if (!first) {
                output.write ('&');
            }
            output.write (URLEncoder.encode (name.toString (), charset));
            output.write ('=');
            if (value != null) {
                output.write (URLEncoder.encode (value.toString (), charset));
            }
        } catch (IOException exception) {
            throw new HttpRequestException (exception);
        }
        return this;
    }

    public Http form (final Map <?, ?> values, final String charset) throws HttpRequestException {
        if (!values.isEmpty ()) {
            for (Entry <?, ?> entry : values.entrySet ()) {
                form (entry, charset);
            }
        }
        return this;
    }

    public Http trustAllCerts () throws HttpRequestException {
        final HttpURLConnection connection = getConnection ();
        if (connection instanceof HttpsURLConnection) {
            ((HttpsURLConnection) connection).setSSLSocketFactory (getTrustedFactory ());
        }
        return this;
    }

    public Http trustAllHosts () {
        final HttpURLConnection connection = getConnection ();
        if (connection instanceof HttpsURLConnection) {
            ((HttpsURLConnection) connection).setHostnameVerifier (getTrustedVerifier());
        }
        return this;
    }

    public URL url () {
        return getConnection ().getURL ();
    }

    public String method () {
        return getConnection ().getRequestMethod ();
    }

    public Http useProxy (final String proxyHost, final int proxyPort) {
        if (connection != null) {
            throw new IllegalStateException ("The connection has already been created. This method must be called before reading or writing to the request.");
        }
        this.httpProxyHost = proxyHost;
        this.httpProxyPort = proxyPort;
        return this;
    }

    public Http followRedirects (final boolean followRedirects) {
        getConnection ().setInstanceFollowRedirects (followRedirects);
        return this;
    }

}
