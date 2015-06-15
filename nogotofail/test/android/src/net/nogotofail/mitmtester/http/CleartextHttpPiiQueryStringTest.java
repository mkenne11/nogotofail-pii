/*
 * Copyright 2014 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.nogotofail.mitmtester.http;

import android.content.Context;
import android.location.Location;

import com.google.android.gms.ads.identifier.AdvertisingIdClient.Info;
import java.net.HttpURLConnection;
import java.net.URL;

import net.nogotofail.mitmtester.BackgroundTestForHttpPii;
import net.nogotofail.mitmtester.R;
import net.nogotofail.mitmtester.util.ClientProperties;

/*
 *  CleartextHttpPiiQueryStringTest simulates the scenario where PII appears
 *  in the query string of HTTP requests.
 */
public class CleartextHttpPiiQueryStringTest extends BackgroundTestForHttpPii {

    protected CleartextHttpPiiQueryStringTest(Context app_context) {
        super(app_context);
    }
    /**
     * Creates a HTTP GET request with PII in query string
     * @throws Exception
     */
    @Override
    protected void runTest() throws Exception {
        HttpURLConnection connection = null;
        URL url;
        try {
            // Get user and device PII for testing
            Context app_context = this.getContext();

            String android_id = ClientProperties.getAndroidId(app_context);
            Info advertising_info = ClientProperties.getAdvertisingId(app_context);
            String google_ad_id = advertising_info.getId();
            Location client_location = ClientProperties.getDeviceLocation(app_context);
            String location_longitude = String.valueOf(client_location.getLongitude());
            String location_latitude = String.valueOf(client_location.getLatitude());
            String email = app_context.getString(R.string.pii_detail_email);

            // Send request with PII identifier in query string
            url = new URL(TARGET + "?google_ad_id=" + google_ad_id);
            connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(CONNECTION_TIMEOUT);
            connection.setReadTimeout(CONNECTION_TIMEOUT);
            setProgressMessage("Issuing HTTP request with with clear-text PII ID in query string");
            setTestResult(connection.getResponseCode() + " " + connection.getResponseMessage());
            connection.disconnect();

            // Send request with PII location in query string
            url = new URL(TARGET + "?longtitude=" + location_longitude +
                "&latitude=" + location_latitude);
            connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(CONNECTION_TIMEOUT);
            connection.setReadTimeout(CONNECTION_TIMEOUT);
            setProgressMessage("Issuing HTTP request with with clear-text PII location in query string");
            setTestResult(connection.getResponseCode() + " " + connection.getResponseMessage());
            connection.disconnect();

            // Send request with PII details in query string
            url = new URL(TARGET + "?email=" + email);
            connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(CONNECTION_TIMEOUT);
            connection.setReadTimeout(CONNECTION_TIMEOUT);
            setProgressMessage("Issuing HTTP request with with clear-text PII detail in query string");
            setTestResult(connection.getResponseCode() + " " + connection.getResponseMessage());
            connection.disconnect();
        }
        finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

}
