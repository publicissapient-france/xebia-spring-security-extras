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
package fr.xebia.fail2ban;

import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.management.MBeanServer;
import javax.management.MBeanServerFactory;
import javax.management.ObjectName;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.concurrent.CustomizableThreadFactory;


/**
 * 
 * @author <a href="mailto:cyrille@cyrilleleclerc.com">Cyrille Le Clerc</a>
 */
public class IpBannerTest {
    private Logger logger = LoggerFactory.getLogger(IpBannerTest.class);

    @Test
    public void test() throws Exception {
        ScheduledExecutorService rotateBucketsAndBanIpsCommandScheduledExecutor = Executors.newScheduledThreadPool(1, new CustomizableThreadFactory(
        "ip-banner-rotator"));
        ScheduledExecutorService cleanerScheduledExecutor = Executors.newScheduledThreadPool(1, new CustomizableThreadFactory(
        "ip-banner-rotator"));
        final Random random = new Random();
        final int numberOfUnfrequentlyFailedIp = 100000;
        final int numberOfFrequentlyFailedIp = 10000;
        final int pounderThreadCount = 50;
        final int pounderPerThreadInvocationCount = 1000000;
        final int pounderPerThreadInvocationThinkTimeInMillis = 25;

        ExecutorService pounderExecutorService = Executors.newFixedThreadPool(pounderThreadCount, new CustomizableThreadFactory("pounder"));

        final IpBanner banner = new IpBanner();
        MBeanServer mbeanServer = getMBeanServer();
        ObjectName bannerObjectName = mbeanServer.registerMBean(banner, new ObjectName("fr.xebia:type=RemoteAddressBanner"))
                .getObjectName();
        try {
            banner.setFindTimeInSeconds(60);
            banner.setBanTimeInSeconds(4);
            banner.setCleanerCommandIntervalInSeconds(4);
            banner.setMaxRetry(11);
            banner.setRotateBucketsAndBanIpsCommandScheduledExecutor(rotateBucketsAndBanIpsCommandScheduledExecutor);
            banner.setCleanerScheduledExecutor(cleanerScheduledExecutor);
            banner.initialize();

            for (int i = 0; i <= pounderThreadCount; i++) {
                Runnable command = new Runnable() {
                    public void run() {
                        for (int i = 0; i < pounderPerThreadInvocationCount; i++) {
                            {
                                String ip = "frequent-ip-" + random.nextInt(numberOfFrequentlyFailedIp);
                                if (banner.isIpBanned(ip)) {
                                    logger.debug("Skip banned ip {}", ip);
                                } else {
                                    banner.incrementFailureCounter(ip);
                                }
                            }
                            {
                                String ip = "unfrequent-ip-" + random.nextInt(numberOfUnfrequentlyFailedIp);
                                if (banner.isIpBanned(ip)) {
                                    logger.debug("Skip banned ip {}", ip);
                                } else {
                                    banner.incrementFailureCounter(ip);
                                }
                            }
                            try {
                                Thread.sleep(random.nextInt(pounderPerThreadInvocationThinkTimeInMillis));
                            } catch (InterruptedException e) {
                                e.printStackTrace();
                            }
                        }
                    };
                };

                pounderExecutorService.execute(command);
            }

            pounderExecutorService.shutdown();
            pounderExecutorService.awaitTermination(30, TimeUnit.MINUTES);
        } finally {
            banner.destroy();
            rotateBucketsAndBanIpsCommandScheduledExecutor.shutdown();            
            cleanerScheduledExecutor.shutdown();

            mbeanServer.unregisterMBean(bannerObjectName);
            logger.error(banner.toString());
        }
    }

    private MBeanServer getMBeanServer() throws RemoteException {
        ArrayList<MBeanServer> mbeanServersList = MBeanServerFactory.findMBeanServer(null);
        MBeanServer mbeanServer;
        if (mbeanServersList.isEmpty()) {
            mbeanServer = MBeanServerFactory.createMBeanServer();
        } else {
            mbeanServer = mbeanServersList.get(0);
        }
        return mbeanServer;
    }
}
