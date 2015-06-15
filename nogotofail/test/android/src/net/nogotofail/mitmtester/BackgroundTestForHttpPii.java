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

package net.nogotofail.mitmtester;

import android.content.Context;

/**
 * Extension of BackgroundTest class with awareness of application context.
 * Note. Application context is needed to access system resources (Device IDs,
 * location) and application resources (strings.xml).
 */
public abstract class BackgroundTestForHttpPii extends BackgroundTest {

    protected static final String TARGET = "http://android.com/";
    protected static final int CONNECTION_TIMEOUT = 10000;

    private Context mContext;

    protected BackgroundTestForHttpPii(Context app_context) {
        mContext = app_context;
    }

    protected abstract void runTest() throws Exception;

    protected Context getContext(){
        return this.mContext;
    }
}
