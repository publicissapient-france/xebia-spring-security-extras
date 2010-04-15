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

import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Java port of <a href="http://www.fail2ban.org/">FailToBan</a>.
 * 
 * @author <a href="mailto:cyrille@cyrilleleclerc.com">Cyrille Le Clerc</a>
 */
public class IpBanner implements IpBannerMBean {

    protected static class Bucket {

        private final long creationTime = System.currentTimeMillis();

        private final ConcurrentMap<String, AtomicInteger> failureCounterByIp = new ConcurrentHashMap<String, AtomicInteger>();

        public long getBucketBeginningTime() {
            return creationTime;
        }

        public ConcurrentMap<String, AtomicInteger> getFailureCounterByIp() {
            return failureCounterByIp;
        }

        @Override
        public String toString() {
            return "Bucket[creationTime: " + this.creationTime + ", bannedIpCount: " + this.failureCounterByIp.size() + "]";
        }
    }

    static private class IpBannerStatistics {
        private final AtomicInteger bannedIpCount = new AtomicInteger();
        private final AtomicInteger batchBannerExecutionCount = new AtomicInteger();
        private final AtomicLong batchBannerTotalDurationInMillis = new AtomicLong();
        private final AtomicInteger cleanerExecutionCount = new AtomicInteger();
        private final AtomicLong cleanerTotalDurationInMillis = new AtomicLong();
        private final AtomicInteger failedAuthenticationCount = new AtomicInteger();

        @Override
        public String toString() {
            return "IpBannerStatistics[" //
                    + "bannedIpCount:" + bannedIpCount + ", " //
                    + "batchBannerExecutionCount: " + batchBannerExecutionCount //
                    + "batchBannerTotalDurationInMillis: " + batchBannerTotalDurationInMillis + ", " //
                    + "cleanerExecutionCount: " + cleanerExecutionCount + ", " //
                    + "cleanerTotalDurationInMillis: " + cleanerTotalDurationInMillis + ", " //
                    + "failedAuthenticationCount: " + failedAuthenticationCount + ", " //
                    + "]";
        }
    }

    private ConcurrentMap<String, Long> bannedIpWithBanishmentTime = new ConcurrentHashMap<String, Long>();

    private long banTimeInMillis = 600;

    private ScheduledFuture<?> batchBannerCommandFuture;

    protected int cleanerCommandIntervalInSeconds = 5;

    private BlockingDeque<Bucket> buckets;

    private int bucketsCount = 6;

    private ScheduledFuture<?> cleanerCommandFuture;

    private int findTimeInSeconds = 600;

    private final Logger logger = LoggerFactory.getLogger(IpBanner.class);

    private int maxRetry = 10;

    private ScheduledExecutorService rotateBucketsAndBanIpsCommandScheduledExecutor;

    private ScheduledExecutorService cleanerScheduledExecutor;

    private final IpBannerStatistics statistics = new IpBannerStatistics();

    public void banIp(String ip) {
        logger.info("Ban {}", ip);
        bannedIpWithBanishmentTime.put(ip, System.currentTimeMillis());
        statistics.bannedIpCount.incrementAndGet();
    }

    protected void clean() {

        long startupTime = System.currentTimeMillis();
        int reenabledIpCounter = 0;

        try {
            long minimumBanishmentTime = System.currentTimeMillis() - banTimeInMillis;
            for (Entry<String, Long> entry : bannedIpWithBanishmentTime.entrySet()) {
                String bannedIp = entry.getKey();
                Long banishmentTime = entry.getValue();
                if (banishmentTime < minimumBanishmentTime) {
                    logger.trace("Reenable banned ip {}", bannedIp);
                    bannedIpWithBanishmentTime.remove(bannedIp, banishmentTime);
                    reenabledIpCounter++;
                }
            }
        } catch (RuntimeException e) {
            logger.error("Exception batch cleaning banned ips", e);
        } finally {
            statistics.cleanerExecutionCount.incrementAndGet();
            long durationInMillis = System.currentTimeMillis() - startupTime;
            statistics.cleanerTotalDurationInMillis.addAndGet(durationInMillis);
            logger.debug("Reenabled {} ips in {} ms", reenabledIpCounter, durationInMillis);
        }

    }

    @PreDestroy
    public void destroy() throws Exception {
        if (this.cleanerCommandFuture != null) {
            this.cleanerCommandFuture.cancel(false);
        }
        if (this.batchBannerCommandFuture != null) {
            this.batchBannerCommandFuture.cancel(false);
        }

        logger.info(getClass().getSimpleName() + " stopped");
    }

    public int getBannedIpCount() {
        return statistics.bannedIpCount.get();
    }

    public int getBanTimeInSeconds() {
        return (int) banTimeInMillis / 1000;
    }

    public int getBatchBannerExecutionCount() {
        return statistics.batchBannerExecutionCount.get();
    }

    public long getBatchBannerTotalDurationInMillis() {
        return statistics.batchBannerTotalDurationInMillis.get();
    }

    public int getCleanerCommandIntervalInSeconds() {
        return cleanerCommandIntervalInSeconds;
    }

    public int getCleanerExecutionCount() {
        return statistics.cleanerExecutionCount.get();
    }

    public long getCleanerTotalDurationInMillis() {
        return statistics.cleanerTotalDurationInMillis.get();
    }

    public int getBucketsCount() {
        return bucketsCount;
    }

    public int getCurrentlyBannedIpsCount() {
        return this.bannedIpWithBanishmentTime.size();
    }

    public int getFailedAuthenticationCount() {
        return statistics.failedAuthenticationCount.get();
    }

    public int getFindTimeInSeconds() {
        return findTimeInSeconds;
    }

    public int getMaxRetry() {
        return maxRetry;
    }

    public IpBannerStatistics getStatistics() {
        return statistics;
    }

    public void incrementFailureCounter(String ip) {

        statistics.failedAuthenticationCount.incrementAndGet();

        Bucket bucket = buckets.peekLast();
        ConcurrentMap<String, AtomicInteger> failureCounterByIp = bucket.getFailureCounterByIp();
        AtomicInteger bucketFailureCounter = failureCounterByIp.get(ip);

        if (bucketFailureCounter == null) {
            bucketFailureCounter = new AtomicInteger();
            AtomicInteger concurrentlyAddedCounter = failureCounterByIp.put(ip, bucketFailureCounter);
            if (concurrentlyAddedCounter != null) {
                bucketFailureCounter = concurrentlyAddedCounter;
            }
        }

        int failureCount = bucketFailureCounter.incrementAndGet();

        if (failureCount > maxRetry) {
            banIp(ip);
        }

    }

    @PostConstruct
    public void initialize() {

        if (this.rotateBucketsAndBanIpsCommandScheduledExecutor == null) {
            throw new IllegalArgumentException("rotateBucketsAndBanIpsCommandScheduledExecutor can NOT be null");
        }
        if (this.cleanerScheduledExecutor == null) {
            throw new IllegalArgumentException("cleanerCommandScheduledExecutor can NOT be null");
        }

        buckets = new LinkedBlockingDeque<Bucket>(bucketsCount);

        Runnable batchBannerCommand = new Runnable() {

            @Override
            public void run() {
                rotateBucketsAndBanIps();
            }
        };
        batchBannerCommandFuture = rotateBucketsAndBanIpsCommandScheduledExecutor.scheduleAtFixedRate(batchBannerCommand, 0,
                findTimeInSeconds * 1000 / bucketsCount, TimeUnit.MILLISECONDS);

        Runnable cleanupBannedIpsCommand = new Runnable() {

            @Override
            public void run() {
                clean();

            }
        };

        cleanerCommandFuture = cleanerScheduledExecutor.scheduleWithFixedDelay(cleanupBannedIpsCommand, 0, cleanerCommandIntervalInSeconds,
                TimeUnit.SECONDS);

        logger.info(getClass().getSimpleName() + " started");
    }

    public boolean isIpBanned(String ip) {
        Long banishmentTime = bannedIpWithBanishmentTime.get(ip);

        boolean banned;
        if (banishmentTime == null) {
            banned = false;
        } else if (System.currentTimeMillis() - banishmentTime > banTimeInMillis) {
            banned = false;
            // cleanup map
            bannedIpWithBanishmentTime.remove(ip);
            logger.debug("Unban {}", ip);
        } else {
            logger.info("{} is banned", ip);
            banned = true;
        }

        return banned;
    }

    protected void rotateBucketsAndBanIps() {
        long startTime = System.currentTimeMillis();

        try {

            // REMOVE OLDEST BUCKET
            Bucket removedBucket;
            if (buckets.remainingCapacity() == 0) {
                removedBucket = buckets.removeFirst();
                logger.debug("Remove {}", removedBucket);
            } else {
                removedBucket = null;
            }

            List<Bucket> bucketsCopy = new ArrayList<Bucket>(buckets);

            // ADD NEW BUCKET
            try {
                buckets.putLast(new Bucket());
            } catch (InterruptedException e) {
                logger.warn("InterruptedException putting new bucket");
            }

            if (removedBucket != null) {

                ConcurrentMap<String, AtomicInteger> aggregatedFailureCounterByIp = removedBucket.getFailureCounterByIp();

                // SCAN BUCKETS TO BAN IP ADDRESSES

                // aggregate failure counts
                for (Bucket bucket : bucketsCopy) {
                    for (Entry<String, AtomicInteger> entry : bucket.getFailureCounterByIp().entrySet()) {
                        String ip = entry.getKey();
                        AtomicInteger perBucketFailureCounter = entry.getValue();

                        AtomicInteger failureCounter = aggregatedFailureCounterByIp.get(ip);
                        if (failureCounter == null) {
                            aggregatedFailureCounterByIp.put(ip, perBucketFailureCounter);
                        } else {
                            failureCounter.addAndGet(perBucketFailureCounter.get());
                        }
                    }
                }

                // ban if aggregated failure count exceeds threshold
                for (Entry<String, AtomicInteger> entry : aggregatedFailureCounterByIp.entrySet()) {
                    String ip = entry.getKey();
                    int failureCount = entry.getValue().get();
                    logger.trace("Evaluate aggregated {} : {} times", ip, failureCount);
                    if (failureCount > maxRetry) {
                        banIp(ip);
                    }
                }
            }
        } finally {
            statistics.batchBannerExecutionCount.incrementAndGet();
            long duration = System.currentTimeMillis() - startTime;
            statistics.batchBannerTotalDurationInMillis.addAndGet(duration);
        }
    }

    public void setRotateBucketsAndBanIpsCommandScheduledExecutor(ScheduledExecutorService rotateBucketsAndBanIpsCommandScheduledExecutor) {
        this.rotateBucketsAndBanIpsCommandScheduledExecutor = rotateBucketsAndBanIpsCommandScheduledExecutor;
    }

    public void setCleanerScheduledExecutor(ScheduledExecutorService cleanerScheduledExecutor) {
        this.cleanerScheduledExecutor = cleanerScheduledExecutor;
    }

    public void setBanTimeInSeconds(int banTimeInSeconds) {
        this.banTimeInMillis = banTimeInSeconds * 1000;
    }

    public void setCleanerCommandIntervalInSeconds(int cleanerCommandIntervalInSeconds) {
        this.cleanerCommandIntervalInSeconds = cleanerCommandIntervalInSeconds;
    }

    public void setBucketsCount(int bucketsCount) {
        if (buckets != null) {
            throw new IllegalStateException("Can not set 'bucketsCount', component already initialized");
        }
        this.bucketsCount = bucketsCount;
    }

    public void setFindTimeInSeconds(int findTimeInSeconds) {
        if (batchBannerCommandFuture != null) {
            throw new IllegalStateException("Can not set 'bucketDurationInSeconds', component already initialized");
        }
        this.findTimeInSeconds = findTimeInSeconds;
    }

    public void setMaxRetry(int maxRetry) {
        this.maxRetry = maxRetry;
    }

    @Override
    public String toString() {
        return "Banner[" //
                + this.statistics.toString() // 
                + "]";
    }
}
