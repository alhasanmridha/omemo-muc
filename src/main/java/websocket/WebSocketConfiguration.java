package websocket;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import org.jivesoftware.smack.ConnectionConfiguration;
import org.jivesoftware.smack.proxy.ProxyInfo;

/**
 * Configuration to use while establishing the connection to the XMPP server via
 * HTTP binding.
 *
 * @see XMPPWebSocketConnection
 * @author Guenther Niess
 */
public final class WebSocketConfiguration extends ConnectionConfiguration {

    private final boolean https;
    private final String file;
    private Map<String, String> httpHeaders;

    private WebSocketConfiguration(WebSocketConfiguration.Builder builder) {
        super(builder);
        if (proxy != null) {
            if (proxy.getProxyType() != ProxyInfo.ProxyType.HTTP) {
                throw new IllegalArgumentException(
                        "Only HTTP proxies are support with BOSH connections");
            }
        }
        https = builder.https;
        if (builder.file.charAt(0) != '/') {
            file = '/' + builder.file;
        } else {
            file = builder.file;
        }
        httpHeaders = builder.httpHeaders;
    }

    public boolean isProxyEnabled() {
        return proxy != null;
    }

    @Override
    public ProxyInfo getProxyInfo() {
        return proxy;
    }

    public String getProxyAddress() {
        return proxy != null ? proxy.getProxyAddress() : null;
    }

    public int getProxyPort() {
        return proxy != null ? proxy.getProxyPort() : 8080;
    }

    public boolean isUsingHTTPS() {
        return https;
    }

    public URI getURI() throws URISyntaxException {
        return new URI((https ? "wss://" : "ws://") + this.host + ":" + this.port + file);
    }

    public Map<String, String> getHttpHeaders() {
        return httpHeaders;
    }

    public static WebSocketConfiguration.Builder builder() {
        return new WebSocketConfiguration.Builder();
    }

    public static final class Builder extends ConnectionConfiguration.Builder<WebSocketConfiguration.Builder, WebSocketConfiguration> {
        private boolean https;
        private String file;
        private Map<String, String> httpHeaders = new HashMap<>();

        private Builder() {
        }

        public WebSocketConfiguration.Builder setUseHttps(boolean useHttps) {
            https = useHttps;
            return this;
        }

        public WebSocketConfiguration.Builder useHttps() {
            return setUseHttps(true);
        }

        public WebSocketConfiguration.Builder setFile(String file) {
            this.file = file;
            return this;
        }

        public WebSocketConfiguration.Builder addHttpHeader(String name, String value) {
            httpHeaders.put(name, value);
            return this;
        }

        @Override
        public WebSocketConfiguration build() {
            return new WebSocketConfiguration(this);
        }

        @Override
        protected WebSocketConfiguration.Builder getThis() {
            return this;
        }
    }
}
