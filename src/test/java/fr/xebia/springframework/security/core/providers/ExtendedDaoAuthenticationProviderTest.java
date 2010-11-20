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

import static org.junit.Assert.fail;

import java.util.Collection;
import java.util.Collections;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import fr.xebia.springframework.security.core.userdetails.ExtendedUser;

public class ExtendedDaoAuthenticationProviderTest {

    @Test
    public void testAdditionalAuthenticationChecksGranted() {
        String allowedRemoteAddresses = "10\\..*";
        String remoteAddr = "10.0.0.1";

        testAdditionalchecks(allowedRemoteAddresses, remoteAddr);
        // ok
    }

    @Test
    public void testAdditionalAuthenticationChecksRejected() {
        String allowedRemoteAddresses = "10\\..*";
        String remoteAddr = "9.0.0.1";

        try {
            testAdditionalchecks(allowedRemoteAddresses, remoteAddr);
            fail("expected exception");
        } catch (BadCredentialsException e) {
            // ok
        }
    }

    private void testAdditionalchecks(String allowedRemoteAddresses, String remoteAddr) {
        ExtendedDaoAuthenticationProvider daoAuthenticationProvider = new ExtendedDaoAuthenticationProvider();

        Collection<GrantedAuthority> grantedAuthorities = Collections.emptyList();

        ExtendedUser extendedUser = new ExtendedUser("test-user", "test-password", true, true, true, true, grantedAuthorities);

        extendedUser.setAllowedRemoteAddresses(allowedRemoteAddresses);

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken("test-user", "test-password");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr(remoteAddr);
        authentication.setDetails(new WebAuthenticationDetails(request));

        daoAuthenticationProvider.additionalAuthenticationChecks(extendedUser, authentication);
    }

}