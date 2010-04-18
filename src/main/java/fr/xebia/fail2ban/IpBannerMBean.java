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

/**
 * Java port of <a href="http://www.fail2ban.org/">FailToBan</a>.
 * 
 * @author <a href="mailto:cyrille@cyrilleleclerc.com">Cyrille Le Clerc</a>
 */
public interface IpBannerMBean {

    void banIp(String remoteAddr);

    /**
     * Duration (in seconds) for IP to be banned for.
     */
    int getBanTimeInSeconds();

    int getBannedIpCount();

    int getCleanerCommandIntervalInSeconds();

    int getBucketCount();

    int getFailedAuthenticationCount();

    /**
     * The counter is set to zero if no match is found within "findtime"
     * seconds.
     */
    int getFindTimeInSeconds();

    void setFindTimeInSeconds(int findTimeInSeconds);

    /**
     * Number of matches (i.e. value of the counter) which triggers ban action
     * on the IP.
     */
    int getMaxRetry();

    boolean isIpBanned(String remoteAddr);

    int getCurrentlyBannedIpsCount();

    void setBanTimeInSeconds(int banTimeInSeconds);

    void setCleanerCommandIntervalInSeconds(int cleanerCommandIntervalInSeconds);

    void setMaxRetry(int failureCountThreshold);

    int getMaxBucketRecycleCount();

    void setMaxBucketRecycleCount(int maxBucketRecycleCount);

    int getFailedIpsQueueSize();
}