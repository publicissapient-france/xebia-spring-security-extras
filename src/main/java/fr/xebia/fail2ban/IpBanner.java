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

import java.util.Iterator;
import java.util.Map.Entry;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadFactory;
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

    protected class Bucket {

        private volatile long bucketChangeNumber = bucketChangeNumberCounter.incrementAndGet();

        private volatile ConcurrentMap<String, AtomicInteger> failureCounterByIp = new ConcurrentHashMap<String, AtomicInteger>();

        private AtomicInteger recycleCounter = new AtomicInteger();

        public long getBucketChangeNumber() {
            return bucketChangeNumber;
        }

        public int getFailureCount(String ip) {
            AtomicInteger atomicInteger = failureCounterByIp.get(ip);
            int failureCount;
            if (atomicInteger == null) {
                failureCount = 0;
            } else {
                failureCount = atomicInteger.get();
            }
            return failureCount;
        }

        public int incrementFailureCountAndGet(String ip) {
            AtomicInteger failureCounter = failureCounterByIp.get(ip);

            if (failureCounter == null) {
                failureCounter = new AtomicInteger();
                // use string.intern() because this String will go in the old
                // objects generation.
                AtomicInteger concurrentlyAddedCounter = failureCounterByIp.put(ip.intern(), failureCounter);
                if (concurrentlyAddedCounter != null) {
                    failureCounter = concurrentlyAddedCounter;
                }
            }
            return failureCounter.incrementAndGet();
        }

        public void recycle() {
            bucketChangeNumber = bucketChangeNumberCounter.incrementAndGet();
            if (recycleCounter.incrementAndGet() > maxBucketRecycleCount) {
                failureCounterByIp = new ConcurrentHashMap<String, AtomicInteger>();
            } else {
                failureCounterByIp.clear();
            }
        }

        @Override
        public String toString() {
            return "Bucket[changeNumber: " + this.bucketChangeNumber + ", bannedIpCount: " + this.failureCounterByIp.size() + "]";
        }
    }

    protected static class NamedThreadFactory implements ThreadFactory {

        private final String namePrefix;

        private final AtomicInteger threadCounter = new AtomicInteger();

        private NamedThreadFactory(String namePrefix) {
            super();
            this.namePrefix = namePrefix;
        }

        @Override
        public Thread newThread(Runnable r) {
            return new Thread(r, namePrefix + "-" + threadCounter.incrementAndGet());
        }
    }

    private AtomicInteger bannedIpCount = new AtomicInteger();

    private ConcurrentMap<String, Long> bannedIpWithBanishmentTime = new ConcurrentHashMap<String, Long>();

    private long banTimeInMillis = 600;

    private AtomicLong bucketChangeNumberCounter = new AtomicLong();

    private int bucketCount = 6;

    /**
     * Visible for test
     */
    protected BlockingDeque<Bucket> buckets;

    private ScheduledFuture<?> cleanerCommandFuture;

    private int cleanerCommandIntervalInSeconds = 5;

    private ScheduledExecutorService cleanerScheduledExecutor;

    private AtomicInteger failedAuthenticationCount = new AtomicInteger();

    private int findTimeInSeconds = 600;

    private final Logger logger = LoggerFactory.getLogger(IpBanner.class);

    private int maxBucketRecycleCount = 50;

    private int maxRetry = 10;

    private ScheduledFuture<?> rotateBucketsCommandFuture;

    private ScheduledExecutorService rotateBucketsExecutor;

    private BlockingQueue<String> failedIps = new LinkedBlockingQueue<String>();

    private Thread failureIncrementorThread;

    private String POISON = new String();

    public IpBanner() {
        rotateBucketsExecutor = Executors.newScheduledThreadPool(1, new NamedThreadFactory("ipbanner-bucket-rotator-"));
        cleanerScheduledExecutor = Executors.newScheduledThreadPool(1, new NamedThreadFactory("ipbanner-banned-ip-cleaner-"));
        Runnable command = new Runnable() {

            @Override
            public void run() {
                while (true) {
                    try {
                        String ip = failedIps.take();
                        if (ip == POISON) {
                            break;
                        } else {
                            try {
                                incrementFailureCounterSync(ip);
                            } catch (RuntimeException e) {
                                logger.error("Exception incrementing failure counter for '" + ip + "'", e);
                            }
                        }
                    } catch (InterruptedException e) {
                        logger.warn("InterruptedException in " + Thread.currentThread().getName() + " thread");
                    }
                }

            }
        };
        failureIncrementorThread = new Thread(command, "ipbanner-banned-ip-failure-incrementor");
        failureIncrementorThread.start();
    }

    public void banIp(String ip) {
        logger.info("Ban {}", ip);
        bannedIpWithBanishmentTime.put(ip, System.currentTimeMillis());
        bannedIpCount.incrementAndGet();
    }

    protected void clean() {

        long startupTime = System.currentTimeMillis();
        int unbannedIpCount = 0;

        try {
            long minimumBanishmentTime = System.currentTimeMillis() - banTimeInMillis;
            for (Entry<String, Long> entry : bannedIpWithBanishmentTime.entrySet()) {
                String bannedIp = entry.getKey();
                Long banishmentTime = entry.getValue();
                if (banishmentTime < minimumBanishmentTime) {
                    logger.info("Unban {}", bannedIp);
                    bannedIpWithBanishmentTime.remove(bannedIp, banishmentTime);
                    unbannedIpCount++;
                }
            }
        } catch (RuntimeException e) {
            logger.error("Exception batch unbanning ips", e);
        } finally {
            long durationInMillis = System.currentTimeMillis() - startupTime;
            logger.debug("Unbanned {} ips in {} ms", unbannedIpCount, durationInMillis);
        }

    }

    @PreDestroy
    public void destroy() throws InterruptedException {
        this.cleanerCommandFuture.cancel(false);
        this.cleanerScheduledExecutor.shutdown();

        this.rotateBucketsCommandFuture.cancel(false);
        this.rotateBucketsExecutor.shutdown();

        this.failedIps.put(POISON);
        this.failureIncrementorThread.join();

        logger.info(getClass().getSimpleName() + " stopped");
    }

    public int getBannedIpCount() {
        return bannedIpCount.get();
    }

    public int getBanTimeInSeconds() {
        return (int) banTimeInMillis / 1000;
    }

    public int getBucketCount() {
        return bucketCount;
    }

    public int getCleanerCommandIntervalInSeconds() {
        return cleanerCommandIntervalInSeconds;
    }

    public int getCurrentlyBannedIpsCount() {
        return this.bannedIpWithBanishmentTime.size();
    }

    public int getFailedAuthenticationCount() {
        return failedAuthenticationCount.get();
    }

    public int getFindTimeInSeconds() {
        return findTimeInSeconds;
    }

    public int getMaxBucketRecycleCount() {
        return maxBucketRecycleCount;
    }

    public int getMaxRetry() {
        return maxRetry;
    }

    public int getFailedIpsQueueSize() {
        return failedIps.size();
    }

    public void incrementFailureCounter(final String ip) {
        try {
            failedIps.put(ip);
        } catch (InterruptedException e) {
            throw new RuntimeException("Exception adding ip '" + ip + "' to the failedIps queue", e);
        }
    }

    protected void incrementFailureCounterSync(String ip) {

        failedAuthenticationCount.incrementAndGet();

        // INCREMENT CURRENT BUCKET FAILURE COUNT
        Iterator<Bucket> firstToLastBucketIterator = buckets.iterator();

        Bucket currentBucket = firstToLastBucketIterator.next();

        int failureCount = currentBucket.incrementFailureCountAndGet(ip);
        if (failureCount > maxRetry) {
            banIp(ip);
            return;
        }

        // ITERATE ON OLDER BUCKETS TO SEE IF MAX_RETRY IS REACHED
        long previousBucketTime = currentBucket.getBucketChangeNumber();

        while (firstToLastBucketIterator.hasNext()) {
            Bucket loopBucket = (Bucket) firstToLastBucketIterator.next();
            if (loopBucket.getBucketChangeNumber() > previousBucketTime) {
                // rotation took place and the loopBucket has been recycled,
                // ignore it
                break;
            } else {
                failureCount += loopBucket.getFailureCount(ip);
                previousBucketTime = loopBucket.getBucketChangeNumber();
                if (failureCount > maxRetry) {
                    banIp(ip);
                    break;
                }
            }
        }
    }

    @PostConstruct
    public void initialize() {

        buckets = new LinkedBlockingDeque<Bucket>(bucketCount);
        buckets.add(new Bucket());

        Runnable rotateBucketsCommand = new Runnable() {

            @Override
            public void run() {
                rotateBuckets();
            }
        };

        int rotateCommandIntervalInMillis = findTimeInSeconds * 1000 / bucketCount;
        rotateBucketsCommandFuture = rotateBucketsExecutor.scheduleAtFixedRate(rotateBucketsCommand, rotateCommandIntervalInMillis,
                rotateCommandIntervalInMillis, TimeUnit.MILLISECONDS);

        Runnable cleanupBannedIpsCommand = new Runnable() {

            @Override
            public void run() {
                clean();

            }
        };

        cleanerCommandFuture = cleanerScheduledExecutor.scheduleWithFixedDelay(cleanupBannedIpsCommand, cleanerCommandIntervalInSeconds,
                cleanerCommandIntervalInSeconds, TimeUnit.SECONDS);

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
            logger.info("Unban {}", ip);
        } else {
            logger.info("{} is banned", ip);
            banned = true;
        }

        return banned;
    }

    protected void rotateBuckets() {

        // REMOVE OLDEST BUCKET IF QUEUE IS FULL
        Bucket bucket;
        if (buckets.remainingCapacity() == 0) {
            bucket = buckets.pollLast();
            logger.debug("Remove {}", bucket);
            // recycle bucket
            bucket.recycle();
        } else {
            bucket = new Bucket();
        }

        // ADD NEW BUCKET
        boolean offered = buckets.offerFirst(bucket);
        if (!offered) {
            logger.warn("failed to insert a new bucket");
        }
    }

    public void setBanTimeInSeconds(int banTimeInSeconds) {
        this.banTimeInMillis = banTimeInSeconds * 1000;
    }

    public void setBucketCount(int bucketCount) {
        if (buckets != null) {
            throw new IllegalStateException("Can not set 'bucketCount', component already initialized");
        }
        this.bucketCount = bucketCount;
    }

    public void setCleanerCommandIntervalInSeconds(int cleanerCommandIntervalInSeconds) {
        this.cleanerCommandIntervalInSeconds = cleanerCommandIntervalInSeconds;
    }

    public void setFindTimeInSeconds(int findTimeInSeconds) {
        if (rotateBucketsCommandFuture != null) {
            throw new IllegalStateException("Can not set 'bucketDurationInSeconds', component already initialized");
        }
        this.findTimeInSeconds = findTimeInSeconds;
    }

    public void setMaxBucketRecycleCount(int maxBucketRecycleCount) {
        this.maxBucketRecycleCount = maxBucketRecycleCount;
    }

    public void setMaxRetry(int maxRetry) {
        this.maxRetry = maxRetry;
    }

    @Override
    public String toString() {
        return "Banner[" //
                + "bannedIpCount:" + bannedIpCount + ", " //
                + "failedAuthenticationCount: " + failedAuthenticationCount + ", " //
                + "bucketChangeNumber: " + this.bucketChangeNumberCounter.get() //
                + "]";
    }
}
