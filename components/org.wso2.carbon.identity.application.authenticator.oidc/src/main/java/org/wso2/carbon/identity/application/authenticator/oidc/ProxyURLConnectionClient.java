/**
 * Copyright (c) 2024, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.application.authenticator.oidc;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.DefaultProxyRoutePlanner;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.util.EntityUtils;
import org.apache.oltu.oauth2.client.HttpClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponseFactory;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.authenticator.oidc.util.ExtendedProxyRoutePlanner;
import org.wso2.carbon.utils.CarbonUtils;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Map;

/**
 * This class holds the logic for applying proxy configs for http connections.
 */
public class ProxyURLConnectionClient implements HttpClient {

    /**
     * Executes the specified OAuth client request and returns the response of the given type.
     * This method processes the OAuth request, handles any exceptions that occur during
     * the process, and provides the response in the form of the specified response class type.
     *
     * @param request The OAuth client request to be executed.
     * @param headers A map of headers to be included with the request. Can be used for authentication,
     *                content type, etc.
     * @param s An additional string parameter that could be used for custom configuration or logging.
     * @param responseClass The class type of the expected response. The method returns an instance of this type
     *                      after processing the request.
     * @param <T> The type of the response that extends OAuthClientResponse.
     * @return An instance of type {@code T} representing the response from the OAuth server.
     * @throws OAuthSystemException If an error occurs during the OAuth system processing.
     * @throws OAuthProblemException If there is a problem with the OAuth request or response.
     */
    @Override
    public <T extends OAuthClientResponse> T execute(OAuthClientRequest request, Map<String, String> headers,
                                                     String s, Class<T> responseClass) throws OAuthSystemException,
            OAuthProblemException {

        org.apache.http.client.HttpClient httpClient = getHttpClient();
        try {
            HttpPost httpPost = new HttpPost(request.getLocationUri());
            if (headers != null && !headers.isEmpty()) {
                for (Map.Entry<String, String> header : headers.entrySet()) {
                    httpPost.setHeader(header.getKey(), header.getValue());
                }
            }
            if (request.getHeaders() != null) {
                for (Map.Entry<String, String> header : request.getHeaders().entrySet()) {
                    httpPost.setHeader(header.getKey(), header.getValue());
                }
            }

            String requestBody = request.getBody();
            if (requestBody != null) {
                StringEntity requestEntity = new StringEntity(requestBody, ContentType.APPLICATION_JSON);
                httpPost.setEntity(requestEntity);

                HttpResponse response = httpClient.execute(httpPost);
                if (HttpStatus.SC_OK == response.getStatusLine().getStatusCode()) {
                    String responseString = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8.name());
                    return OAuthClientResponseFactory
                            .createCustomResponse(responseString, requestEntity.getContentType().toString(),
                                    response.getStatusLine().getStatusCode(), responseClass);
                } else {
                    throw new OAuthSystemException("Error while obtaining the access token through the proxy " +
                            EntityUtils.toString(response.getEntity()));
                }
            } else {
                throw new OAuthSystemException("Request body can not be null");
            }
        } catch (IOException e) {
            throw new OAuthSystemException(e);
        }
    }

    @Override
    public void shutdown() {
        // Nothing to do here
    }

    private static org.apache.http.client.HttpClient getHttpClient() throws OAuthSystemException {

        String proxyHost = null;
        String proxyProtocol = null;
        String proxyUsername = null;
        String proxyPassword = null;
        String proxyPort = null;
        String nonProxyHosts = null;

        if ((proxyHost = System.getProperty(OIDCAuthenticatorConstants.Proxy.HTTP.PROXY_HOST)) != null) {
            proxyProtocol = OIDCAuthenticatorConstants.Proxy.HTTP.PROTOCOL;
            if ((proxyPort = System.getProperty(OIDCAuthenticatorConstants.Proxy.HTTP.PROXY_PORT)) == null) {
                proxyPort = OIDCAuthenticatorConstants.Proxy.HTTP.DEFAULT_PROXY_PORT;
            }
            proxyUsername = System.getProperty(OIDCAuthenticatorConstants.Proxy.HTTP.PROXY_USERRNAME);
            proxyPassword = System.getProperty(OIDCAuthenticatorConstants.Proxy.HTTP.PROXY_PASSWORD);
            nonProxyHosts = System.getProperty(OIDCAuthenticatorConstants.Proxy.HTTP.NON_PROXY_HOSTS);
        } else if ((proxyHost = System.getProperty(OIDCAuthenticatorConstants.Proxy.HTTPS.PROXY_HOST)) != null) {
            proxyProtocol = OIDCAuthenticatorConstants.Proxy.HTTPS.PROTOCOL;
            if ((proxyPort = System.getProperty(OIDCAuthenticatorConstants.Proxy.HTTPS.PROXY_PORT)) == null) {
                proxyPort = OIDCAuthenticatorConstants.Proxy.HTTPS.DEFAULT_PROXY_PORT;
            }
            proxyUsername = System.getProperty(OIDCAuthenticatorConstants.Proxy.HTTPS.PROXY_USERRNAME);
            proxyPassword = System.getProperty(OIDCAuthenticatorConstants.Proxy.HTTPS.PROXY_PASSWORD);
            nonProxyHosts = System.getProperty(OIDCAuthenticatorConstants.Proxy.HTTPS.NON_PROXY_HOSTS);
        }

        PoolingHttpClientConnectionManager pool = null;
        try {
            pool = getPoolingHttpClientConnectionManager(proxyProtocol);
        } catch (Exception e) {
            throw new OAuthSystemException(e);
        }

        RequestConfig params = RequestConfig.custom().build();
        HttpClientBuilder clientBuilder = HttpClients.custom().setConnectionManager(pool)
                .setDefaultRequestConfig(params);

        HttpHost host = new HttpHost(proxyHost, Integer.parseInt(proxyPort), proxyProtocol);
        clientBuilder.setDefaultRequestConfig(RequestConfig.custom().setProxy(host).build());
        DefaultProxyRoutePlanner routePlanner;
        if (!StringUtils.isBlank(nonProxyHosts)) {
            routePlanner = new ExtendedProxyRoutePlanner(host, nonProxyHosts, proxyHost, proxyPort, proxyProtocol);
        } else {
            routePlanner = new DefaultProxyRoutePlanner(host);
        }
        clientBuilder = clientBuilder.setRoutePlanner(routePlanner);
        if (!StringUtils.isBlank(proxyUsername) && !StringUtils.isBlank(proxyPassword)) {
            CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
            credentialsProvider.setCredentials(new AuthScope(proxyHost, Integer.parseInt(proxyPort)),
                    new UsernamePasswordCredentials(proxyUsername, proxyPassword));
            clientBuilder = clientBuilder.setDefaultCredentialsProvider(credentialsProvider);
        }
        return clientBuilder.build();
    }

    /**
     * Return a PoolingHttpClientConnectionManager instance
     *
     * @param protocol- service endpoint protocol. It can be http/https
     * @return PoolManager
     */
    private static PoolingHttpClientConnectionManager getPoolingHttpClientConnectionManager(String protocol)
            throws Exception {

        PoolingHttpClientConnectionManager poolManager;
        if (OIDCAuthenticatorConstants.Proxy.HTTPS.PROTOCOL.equals(protocol)) {
            SSLConnectionSocketFactory socketFactory = createSocketFactory();
            org.apache.http.config.Registry<ConnectionSocketFactory> socketFactoryRegistry =
                    RegistryBuilder.<ConnectionSocketFactory>create()
                            .register(OIDCAuthenticatorConstants.Proxy.HTTPS.PROTOCOL, socketFactory).build();
            poolManager = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
        } else {
            poolManager = new PoolingHttpClientConnectionManager();
        }
        return poolManager;
    }

    private static SSLConnectionSocketFactory createSocketFactory() throws OAuthSystemException {

        SSLContext sslContext = null;
        HostnameVerifier hostnameVerifier = null;
        String keyStorePath = CarbonUtils.getServerConfiguration()
                .getFirstProperty(OIDCAuthenticatorConstants.Proxy.trustStoreLocation);
        String keyStorePassword = CarbonUtils.getServerConfiguration()
                .getFirstProperty(OIDCAuthenticatorConstants.Proxy.trustStorePassword);
        try {
            KeyStore trustStore = KeyStore.getInstance("JKS");
            try (FileInputStream keyStoreFileInputStream = new FileInputStream(keyStorePath)) {
                trustStore.load(keyStoreFileInputStream, keyStorePassword.toCharArray());
            }
            sslContext = SSLContexts.custom().loadTrustMaterial(trustStore).build();
            String hostnameVerifierOption = System.getProperty(OIDCAuthenticatorConstants.Proxy.hostNameVerifierSysEnv);

            if (OIDCAuthenticatorConstants.Proxy.ALLOW_ALL_HOSTNAME_VERIFIER.equalsIgnoreCase(hostnameVerifierOption)) {
                hostnameVerifier = SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
            } else if (OIDCAuthenticatorConstants.Proxy.STRICT_HOSTNAME_VERIFIER.equalsIgnoreCase(hostnameVerifierOption)) {
                hostnameVerifier = SSLSocketFactory.STRICT_HOSTNAME_VERIFIER;
            } else if (OIDCAuthenticatorConstants.Proxy.DEFAULT_HOSTNAME_VERIFIER.equalsIgnoreCase(hostnameVerifierOption)) {
                hostnameVerifier = new HostnameVerifier() {
                    final String[] localhosts = {"::1", "127.0.0.1", "localhost", "localhost.localdomain"};

                    @Override
                    public boolean verify(String urlHostName, SSLSession session) {
                        return SSLSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER.verify(urlHostName, session)
                                || Arrays.asList(localhosts).contains(urlHostName);
                    }
                };
            } else {
                hostnameVerifier = SSLSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER;
            }
            return new SSLConnectionSocketFactory(sslContext, (X509HostnameVerifier) hostnameVerifier);

        } catch (Exception e) {
            throw new OAuthSystemException(e);
        }
    }
}