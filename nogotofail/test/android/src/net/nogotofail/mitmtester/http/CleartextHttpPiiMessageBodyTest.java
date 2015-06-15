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

import net.nogotofail.mitmtester.BackgroundTestForHttpPii;
import net.nogotofail.mitmtester.R;
import net.nogotofail.mitmtester.util.ClientProperties;

import java.io.InputStream;
import org.json.JSONObject;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicHeader;
import org.apache.http.protocol.HTTP;

/*
 *  CleartextHttpPiiMessageBodyTest simulates the scenario where PII appears
 *  in the message bodies of unecrypted HTTP requests and responses.
 */
public class CleartextHttpPiiMessageBodyTest extends BackgroundTestForHttpPii {

    protected CleartextHttpPiiMessageBodyTest(Context app_context) {
        super(app_context);
    }

    /**
     * Creates a HTTP POST request with PII in message body
     * @throws Exception
     */
    @Override
    protected void runTest() throws Exception {
        Context app_context = this.getContext();

        // Get user and device PII for testing
        String android_id = ClientProperties.getAndroidId(app_context);
        AdvertisingIdClient.Info advertising_info = ClientProperties.getAdvertisingId(app_context);
        String google_ad_id = advertising_info.getId();
        Location client_location = ClientProperties.getDeviceLocation(app_context);
        String location_longitude = String.valueOf(client_location.getLongitude());
        String location_latitude = String.valueOf(client_location.getLatitude());
        String email = app_context.getString(R.string.pii_detail_email);

        HttpClient client = new DefaultHttpClient();
        HttpConnectionParams.setConnectionTimeout(client.getParams(), CONNECTION_TIMEOUT); //Timeout Limit
        HttpResponse response;
        JSONObject json_data;
        int response_code;
        String response_message;

        // Send PII identifiers in HTTP POST request
        try {
            HttpPost post = new HttpPost(TARGET);
            json_data = new JSONObject();
            json_data.put("google_ad_id", google_ad_id);
            StringEntity se = new StringEntity(json_data.toString());
            se.setContentType(new BasicHeader(HTTP.CONTENT_TYPE, "application/json"));
            post.setEntity(se);
            setProgressMessage("Issuing HTTP request with with clear-text PII identifiers in " +
                    "message body");
            response = client.execute(post);

            // Checking response
            if(response!=null){
                //Get the data in the entity
                InputStream in = response.getEntity().getContent();
                response_code = response.getStatusLine().getStatusCode();
                response_message = response.getStatusLine().getReasonPhrase();
                setTestResult(Integer.toString(response_code) + " " + response_message);
            }
        } catch(Exception e) {
            e.printStackTrace();
        }

        // Send PII location in HTTP POST request
        try {
            HttpPost post = new HttpPost(TARGET);
            json_data = new JSONObject();
            json_data.put("location_longitude", location_longitude);
            json_data.put("location_latitude", location_latitude);
            StringEntity se = new StringEntity(json_data.toString());
            se.setContentType(new BasicHeader(HTTP.CONTENT_TYPE, "application/json"));
            post.setEntity(se);
            setProgressMessage("Issuing HTTP request with with clear-text PII location in " +
                    "message body");
            response = client.execute(post);

            // Checking response
            if(response!=null){
                //Get the data in the entity
                InputStream in = response.getEntity().getContent();
                response_code = response.getStatusLine().getStatusCode();
                response_message = response.getStatusLine().getReasonPhrase();
                setTestResult(Integer.toString(response_code) + " " + response_message);
            }
        } catch(Exception e) {
            e.printStackTrace();
        }

        // Send PII details in HTTP POST request
        try {
            HttpPost post = new HttpPost(TARGET);
            json_data = new JSONObject();
            json_data.put("email", email);
            StringEntity se = new StringEntity(json_data.toString());
            se.setContentType(new BasicHeader(HTTP.CONTENT_TYPE, "application/json"));
            post.setEntity(se);
            setProgressMessage("Issuing HTTP request with with clear-text PII details in " +
                    "message body");
            response = client.execute(post);

            // Checking response
            if(response!=null){
                //Get the data in the entity
                InputStream in = response.getEntity().getContent();
                response_code = response.getStatusLine().getStatusCode();
                response_message = response.getStatusLine().getReasonPhrase();
                setTestResult(Integer.toString(response_code) + " " + response_message);
            }
        } catch(Exception e) {
            e.printStackTrace();
        }
    }

}
