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
package fr.xebia.springframework.security.core.providers;

import java.util.List;
import java.util.regex.Pattern;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import fr.xebia.springframework.security.core.userdetails.ExtendedUser;

/**
 * Verify that the {@link WebAuthenticationDetails#getRemoteAddress()} matches
 * on of the {@link ExtendedUser#getAllowedRemoteAddresses()} in the
 * {@link #additionalAuthenticationChecks(UserDetails, UsernamePasswordAuthenticationToken)}
 * phase.
 * 
 * @see ExtendedUser
 * @author <a href="mailto:cyrille@cyrilleleclerc.com">Cyrille Le Clerc</a>
 */
public class ExtendedDaoAuthenticationProvider extends DaoAuthenticationProvider {

    protected final Log log = LogFactory.getLog(getClass());

    /**
     * Checks that the {@link WebAuthenticationDetails#getRemoteAddress()}
     * matches one of the {@link ExtendedUser#getAllowedRemoteAddresses()}. If
     * the given <code>userDetails</code> is not an {@link ExtendedUser} of if
     * the given <code>authentication.details</code> is not a
     * {@link WebAuthenticationDetails}, then the ip address check is silently
     * by passed.
     */
    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication)
            throws AuthenticationException {

        super.additionalAuthenticationChecks(userDetails, authentication);

        if (!(userDetails instanceof ExtendedUser)) {
            if (log.isDebugEnabled()) {
                log.debug("Given userDetails '" + userDetails + "' is not an ExtendedUser, skip ipAddress verification");
            }
            return;
        }
        ExtendedUser extendedUser = (ExtendedUser) userDetails;

        if (!(authentication.getDetails() instanceof WebAuthenticationDetails)) {
            if (log.isDebugEnabled()) {
                log.debug("Given authentication '" + authentication
                        + "' does not hold WebAuthenticationDetails, skip ipAddress verification");
            }
            return;
        }
        WebAuthenticationDetails webAuthenticationDetails = (WebAuthenticationDetails) authentication.getDetails();

        String remoteIpAddress = webAuthenticationDetails.getRemoteAddress();

        if (log.isDebugEnabled()) {
            log.debug("Evaluate permission for '" + extendedUser + "' to authenticate from ip address " + remoteIpAddress);
        }

        List<Pattern> allowedRemoteAddressesPatterns = extendedUser.getAllowedRemoteAddressesPatterns();
        if (!matchesOneAddress(remoteIpAddress, allowedRemoteAddressesPatterns)) {
            throw new BadCredentialsException("Access denied from IP : " + remoteIpAddress);
        }
    }

    /**
     * Returns <code>true</code> if the given <code>ipAddress</code> matches one
     * of the given <code>allowedIpAddresses</code> or if the given
     * <code>allowedIpAddresses</code> list is empty.
     */
    protected boolean matchesOneAddress(String ipAddress, List<Pattern> allowedIpAddresses) {
        if (allowedIpAddresses.isEmpty()) {
            return true;
        }
        for (Pattern allowedIpAddress : allowedIpAddresses) {
            if (allowedIpAddress.matcher(ipAddress).matches()) {
                return true;
            }
        }
        return false;
    }

}
