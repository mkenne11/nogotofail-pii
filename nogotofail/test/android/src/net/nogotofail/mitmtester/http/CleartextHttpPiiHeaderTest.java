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
import com.google.android.gms.ads.identifier.AdvertisingIdClient;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

import net.nogotofail.mitmtester.BackgroundTestForHttpPii;
import net.nogotofail.mitmtester.R;
import net.nogotofail.mitmtester.util.ClientProperties;

/*
 *  CleartextHttpPiiHeaderTest simulates the scenario where PII appears
 *  in the headers of unecrypted HTTP requests.
 */
public class CleartextHttpPiiHeaderTest extends BackgroundTestForHttpPii {

    protected CleartextHttpPiiHeaderTest(Context app_context) {
        super(app_context);
    }

    /**
     * Creates a HTTP GET request with PII in request header
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
            AdvertisingIdClient.Info advertising_info = ClientProperties.getAdvertisingId(app_context);
            String google_ad_id = advertising_info.getId();
            Location client_location = ClientProperties.getDeviceLocation(app_context);
            String location_longitude = String.valueOf(client_location.getLongitude());
            String location_latitude = String.valueOf(client_location.getLatitude());
            String email = app_context.getString(R.string.pii_detail_email);

            InputStream input_stream;
            // Send request with PII identifier in HTTP header
            url = new URL(TARGET);
            connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(CONNECTION_TIMEOUT);
            connection.setReadTimeout(CONNECTION_TIMEOUT);
            connection.setRequestProperty("Header-Identifier", google_ad_id);
            setProgressMessage("Issuing HTTP request with with clear-text PII ID in header");
            setTestResult(connection.getResponseCode() + " " + connection.getResponseMessage());
            connection.disconnect();

            // Send request with PII location in HTTP header
            url = new URL(TARGET);
            connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(CONNECTION_TIMEOUT);
            connection.setReadTimeout(CONNECTION_TIMEOUT);
            connection.setRequestProperty("Header-Longitude", location_longitude);
            connection.setRequestProperty("Header-Latitude", location_latitude);
            setProgressMessage("Issuing HTTP request with with clear-text PII location in header");
            setTestResult(connection.getResponseCode() + " " + connection.getResponseMessage());
            connection.disconnect();

            // Send request with PII detail in HTTP header
            url = new URL(TARGET);
            connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(CONNECTION_TIMEOUT);
            connection.setReadTimeout(CONNECTION_TIMEOUT);
            connection.setRequestProperty("Header-Detail", email);
            setProgressMessage("Issuing HTTP request with with clear-text PII details in header");
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
