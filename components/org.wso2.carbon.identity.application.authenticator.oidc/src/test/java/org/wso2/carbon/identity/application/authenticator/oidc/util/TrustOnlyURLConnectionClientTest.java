/**
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.oidc.util;

import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.mockito.ArgumentCaptor;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.powermock.reflect.Whitebox;
import org.testng.IObjectFactory;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

import static org.mockito.Mockito.verify;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;

/**
 * Unit tests for {@link TrustOnlyURLConnectionClient}.
 */
@PrepareForTest({URL.class, TrustOnlyURLConnectionClient.class})
@PowerMockIgnore({"javax.net.ssl.*", "javax.security.*", "javax.crypto.*"})
public class TrustOnlyURLConnectionClientTest extends PowerMockTestCase {

    private static final String TOKEN_ENDPOINT = "https://idp.example.com/token";
    private static final String RESPONSE_BODY = "{\"access_token\":\"test-token\",\"token_type\":\"bearer\"}";

    @Test
    public void testNoArgConstructorDefaultsToNoTimeout() throws Exception {

        TrustOnlyURLConnectionClient client = new TrustOnlyURLConnectionClient();

        assertEquals((int) Whitebox.getInternalState(client, "connectTimeoutMillis"), 0,
                "Default connect timeout must match URLConnectionClient's (no timeout).");
        assertEquals((int) Whitebox.getInternalState(client, "readTimeoutMillis"), 0,
                "Default read timeout must match URLConnectionClient's (no timeout).");
    }

    @Test
    public void testCustomTimeoutsAreStored() throws Exception {

        TrustOnlyURLConnectionClient client = new TrustOnlyURLConnectionClient(3000, 4000);

        assertEquals((int) Whitebox.getInternalState(client, "connectTimeoutMillis"), 3000);
        assertEquals((int) Whitebox.getInternalState(client, "readTimeoutMillis"), 4000);
    }

    @Test
    public void testRejectsNegativeConnectTimeout() {

        try {
            new TrustOnlyURLConnectionClient(-1, 1000);
            fail("Expected IllegalArgumentException for negative connectTimeoutMillis");
        } catch (IllegalArgumentException e) {
            assertNotNull(e.getMessage());
        }
    }

    @Test
    public void testRejectsNegativeReadTimeout() {

        try {
            new TrustOnlyURLConnectionClient(1000, -1);
            fail("Expected IllegalArgumentException for negative readTimeoutMillis");
        } catch (IllegalArgumentException e) {
            assertNotNull(e.getMessage());
        }
    }

    @Test
    public void testExecuteAppliesTrustOnlySslSocketFactoryForHttpsAndReturnsResponse() throws Exception {

        HttpsURLConnection mockConnection = mock(HttpsURLConnection.class);
        URL mockUrl = mock(URL.class);
        whenNew(URL.class).withArguments(TOKEN_ENDPOINT).thenReturn(mockUrl);
        when(mockUrl.openConnection()).thenReturn(mockConnection);
        when(mockConnection.getResponseCode()).thenReturn(200);
        when(mockConnection.getInputStream()).thenReturn(
                new ByteArrayInputStream(RESPONSE_BODY.getBytes(StandardCharsets.UTF_8)));
        when(mockConnection.getContentType()).thenReturn("application/json");
        when(mockConnection.getOutputStream()).thenReturn(new ByteArrayOutputStream());

        OAuthClientRequest request = buildTokenRequest();

        OAuthJSONAccessTokenResponse response = new TrustOnlyURLConnectionClient()
                .execute(request, Collections.emptyMap(), "POST", OAuthJSONAccessTokenResponse.class);

        assertNotNull(response);
        assertEquals(response.getAccessToken(), "test-token");

        ArgumentCaptor<SSLSocketFactory> factoryCaptor = ArgumentCaptor.forClass(SSLSocketFactory.class);
        verify(mockConnection).setSSLSocketFactory(factoryCaptor.capture());
        assertNotNull(factoryCaptor.getValue());
        verify(mockConnection).connect();
    }

    @Test
    public void testExecuteWorksForPlainHttpConnectionWithoutSettingSslSocketFactory() throws Exception {

        HttpURLConnection mockConnection = mock(HttpURLConnection.class);
        URL mockUrl = mock(URL.class);
        whenNew(URL.class).withArguments(TOKEN_ENDPOINT).thenReturn(mockUrl);
        when(mockUrl.openConnection()).thenReturn(mockConnection);
        when(mockConnection.getResponseCode()).thenReturn(200);
        when(mockConnection.getInputStream()).thenReturn(
                new ByteArrayInputStream(RESPONSE_BODY.getBytes(StandardCharsets.UTF_8)));
        when(mockConnection.getContentType()).thenReturn("application/json");
        when(mockConnection.getOutputStream()).thenReturn(new ByteArrayOutputStream());

        OAuthClientRequest request = buildTokenRequest();

        OAuthJSONAccessTokenResponse response = new TrustOnlyURLConnectionClient()
                .execute(request, Collections.emptyMap(), "POST", OAuthJSONAccessTokenResponse.class);

        assertNotNull(response);
        assertEquals(response.getAccessToken(), "test-token");
        verify(mockConnection).connect();
    }

    private OAuthClientRequest buildTokenRequest() throws Exception {

        return OAuthClientRequest.tokenLocation(TOKEN_ENDPOINT)
                .setGrantType(GrantType.AUTHORIZATION_CODE)
                .setClientId("client-id")
                .setClientSecret("client-secret")
                .setRedirectURI("https://sp.example.com/callback")
                .setCode("auth-code")
                .buildBodyMessage();
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }
}
