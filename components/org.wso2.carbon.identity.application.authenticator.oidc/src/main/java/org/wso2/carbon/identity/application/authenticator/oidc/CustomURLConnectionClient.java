/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.oidc;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.apache.oltu.oauth2.client.HttpClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponseFactory;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.utils.OAuthUtils;

public class CustomURLConnectionClient implements HttpClient {

    @Override
    public <T extends OAuthClientResponse> T execute(OAuthClientRequest request,
                                                     Map<String, String> headers,
                                                     String requestMethod,
                                                     Class<T> responseClass)
            throws OAuthSystemException, OAuthProblemException {

        String responseBody = null;
        URLConnection c = null;
        int responseCode = 0;

        try {
            URL url = new URL(request.getLocationUri());
            c = url.openConnection();

            // For HTTPS, force an SSLContext that never presents a client cert,
            // while keeping the default JVM truststore behavior.
            if (c instanceof HttpsURLConnection) {
                HttpsURLConnection https = (HttpsURLConnection) c;

                TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                        TrustManagerFactory.getDefaultAlgorithm()
                );
                // Use default JVM truststore (same behavior as HttpsURLConnection defaults)
                tmf.init((KeyStore) null);

                SSLContext sc = SSLContext.getInstance("TLS");
                // KeyManagers = null => no client certificate will ever be presented
                sc.init(null, tmf.getTrustManagers(), new SecureRandom());

                https.setSSLSocketFactory(sc.getSocketFactory());
                // Keep default hostname verifier (recommended)
                https.setHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier());
            }

            responseCode = -1;

            if (c instanceof HttpURLConnection) {
                HttpURLConnection httpURLConnection = (HttpURLConnection) c;

                if (headers != null && !headers.isEmpty()) {
                    for (Map.Entry<String, String> header : headers.entrySet()) {
                        httpURLConnection.addRequestProperty(header.getKey(), header.getValue());
                    }
                }

                if (request.getHeaders() != null) {
                    for (Map.Entry<String, String> header : request.getHeaders().entrySet()) {
                        httpURLConnection.addRequestProperty(header.getKey(), header.getValue());
                    }
                }

                if (!OAuthUtils.isEmpty(requestMethod)) {
                    httpURLConnection.setRequestMethod(requestMethod);
                    if ("POST".equals(requestMethod)) {
                        httpURLConnection.setDoOutput(true);
                        try (OutputStream ost = httpURLConnection.getOutputStream();
                             PrintWriter pw = new PrintWriter(ost)) {
                            pw.print(request.getBody());
                            pw.flush();
                        }
                    }
                } else {
                    httpURLConnection.setRequestMethod("GET");
                }

                httpURLConnection.connect();
                responseCode = httpURLConnection.getResponseCode();

                InputStream inputStream;
                if (responseCode != 400 && responseCode != 401) {
                    inputStream = httpURLConnection.getInputStream();
                } else {
                    inputStream = httpURLConnection.getErrorStream();
                }

                responseBody = OAuthUtils.saveStreamAsString(inputStream);
            }

        } catch (Exception e) {
            // Includes IOException + SSL/crypto exceptions
            throw new OAuthSystemException(e);
        }

        return OAuthClientResponseFactory.createCustomResponse(
                responseBody,
                c != null ? c.getContentType() : null,
                responseCode,
                responseClass
        );
    }

    @Override
    public void shutdown() {
        // no-op
    }
}
