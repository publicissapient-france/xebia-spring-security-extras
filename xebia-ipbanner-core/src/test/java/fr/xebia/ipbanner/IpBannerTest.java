/*
 * Copyright 2008-2009 Xebia and the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package fr.xebia.ipbanner;

import java.util.concurrent.LinkedBlockingDeque;

import org.junit.Assert;
import org.junit.Test;

import fr.xebia.ipbanner.IpBanner.Bucket;

/**
 * 
 * @author <a href="mailto:cyrille@cyrilleleclerc.com">Cyrille Le Clerc</a>
 */
public class IpBannerTest {
    
    private int asyncPropagationDelayInMillis = 10;

    @Test
    public void testBanWithAllFailuresTheSoleBucket() throws Exception {
        int maxRetry = 11;
        int bucketCount = 6;

        final IpBanner banner = new IpBanner();
        banner.setBanTimeInSeconds(4);
        banner.buckets = new LinkedBlockingDeque<Bucket>(bucketCount);
        banner.rotateBuckets();

        banner.setMaxRetry(maxRetry);

        for (int i = 0; i < maxRetry; i++) {
            banner.incrementFailureCounterSync("9.0.0.1");
            Assert.assertFalse("ip must NOT be banned after " + (i + 1) + " failures", banner.isIpBanned("9.0.0.1"));
        }
        banner.incrementFailureCounterSync("9.0.0.1");
        Thread.sleep(asyncPropagationDelayInMillis);
        Assert.assertTrue("ip must be banned", banner.isIpBanned("9.0.0.1"));
    }

    @Test
    public void testBanWithOneFailurePerBucket() throws Exception {
        int maxRetry = 5;
        int bucketCount = 6;

        final IpBanner banner = new IpBanner();
        banner.setBanTimeInSeconds(4);
        banner.buckets = new LinkedBlockingDeque<Bucket>(bucketCount);
        banner.rotateBuckets();

        banner.setMaxRetry(maxRetry);

        Assert.assertTrue("maxRetry<bucketCount", maxRetry < bucketCount);

        for (int i = 0; i < maxRetry; i++) {
            banner.incrementFailureCounterSync("9.0.0.1");
            Thread.sleep(asyncPropagationDelayInMillis);
            Assert.assertFalse("ip must NOT be banned after " + (i + 1) + " failures", banner.isIpBanned("9.0.0.1"));
            banner.rotateBuckets();
        }
        banner.incrementFailureCounterSync("9.0.0.1");
        Thread.sleep(asyncPropagationDelayInMillis);
        Assert.assertTrue("ip must be banned", banner.isIpBanned("9.0.0.1"));
    }

    @Test
    public void testBanWithOneFailureEveryTwoBucket() throws Exception {
        int maxRetry = 5;
        int bucketCount = 12;

        final IpBanner banner = new IpBanner();
        banner.setBanTimeInSeconds(4);
        banner.buckets = new LinkedBlockingDeque<Bucket>(bucketCount);
        banner.rotateBuckets();

        banner.setMaxRetry(maxRetry);

        Assert.assertTrue("maxRetry<bucketCount", 2 * maxRetry < bucketCount);

        for (int i = 0; i < maxRetry; i++) {
            banner.incrementFailureCounterSync("9.0.0.1");
            Thread.sleep(asyncPropagationDelayInMillis);

            Assert.assertFalse("ip must NOT be banned after " + (i + 1) + " failures", banner.isIpBanned("9.0.0.1"));
            banner.rotateBuckets();
            banner.rotateBuckets();
        }
        banner.incrementFailureCounterSync("9.0.0.1");
        Thread.sleep(asyncPropagationDelayInMillis);

        Assert.assertTrue("ip must be banned", banner.isIpBanned("9.0.0.1"));
    }
}
