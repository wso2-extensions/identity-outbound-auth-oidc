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

import org.mockito.ArgumentCaptor;
import org.powermock.reflect.Whitebox;
import org.testng.annotations.Test;

import java.net.HttpURLConnection;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertSame;

/**
 * Unit tests for {@link TrustOnlySslUtils}.
 */
public class TrustOnlySslUtilsTest {

    @Test
    public void testNoOpForNonHttpsConnection() throws Exception {

        HttpURLConnection connection = mock(HttpURLConnection.class);

        TrustOnlySslUtils.applyTrustOnlySslIfHttps(connection);

        verifyZeroInteractions(connection);
    }

    @Test
    public void testAppliesTrustOnlySslSocketFactoryForHttpsConnection() throws Exception {

        HttpsURLConnection connection = mock(HttpsURLConnection.class);

        TrustOnlySslUtils.applyTrustOnlySslIfHttps(connection);

        ArgumentCaptor<SSLSocketFactory> factoryCaptor = ArgumentCaptor.forClass(SSLSocketFactory.class);
        verify(connection).setSSLSocketFactory(factoryCaptor.capture());
        assertNotNull(factoryCaptor.getValue());
    }

    @Test
    public void testReusesCachedTrustOnlySslContextAcrossConnections() throws Exception {

        // getTrustOnlySslContext() is package-private; invoke directly to verify the SSLContext itself is
        // cached and reused (SSLContext.getSocketFactory() legitimately returns a new wrapper instance on
        // every call even for the same context, so socket-factory identity is not a valid proxy for this).
        SSLContext first = Whitebox.invokeMethod(TrustOnlySslUtils.class, "getTrustOnlySslContext");
        SSLContext second = Whitebox.invokeMethod(TrustOnlySslUtils.class, "getTrustOnlySslContext");

        assertSame(second, first, "The trust-only SSLContext should be built once and reused across calls.");
    }
}
