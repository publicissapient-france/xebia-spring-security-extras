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
package fr.xebia.springframework.security.core.userdetails;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Extension of {@link org.springframework.security.core.userdetails.User} to add a list of allowed remote ip adresses.
 *
 * @author <a href="mailto:cyrille@cyrilleleclerc.com">Cyrille Le Clerc</a>
 */
public class ExtendedUser extends User implements UserDetails {

    private static final long serialVersionUID = 1L;

    protected List<Pattern> allowedRemoteAddresses = new ArrayList<Pattern>();

    protected String comments;

    public ExtendedUser(String username, String password, boolean enabled, boolean accountNonExpired, boolean credentialsNonExpired,
            boolean accountNonLocked, Collection<GrantedAuthority> authorities) throws IllegalArgumentException {
        super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
    }

    /**
     * Override for FindBugs EQ_DOESNT_OVERRIDE_EQUALS
     */
    @Override
    public boolean equals(Object rhs) {
        return super.equals(rhs);
    }

    public String getAllowedRemoteAddresses() {
        return StringUtils.collectionToCommaDelimitedString(allowedRemoteAddresses);
    }

    public List<Pattern> getAllowedRemoteAddressesPatterns() {
        return allowedRemoteAddresses;
    }

    public String getComments() {
        return comments;
    }

    /**
     * Override for FindBugs EQ_DOESNT_OVERRIDE_EQUALS
     */
    @Override
    public int hashCode() {
        return super.hashCode();
    }

    public void setAllowedRemoteAddresses(List<Pattern> allowedRemoteAddresses) {
        this.allowedRemoteAddresses = allowedRemoteAddresses;
    }

    public void setAllowedRemoteAddresses(String allowedRemoteAddresses) {
        allowedRemoteAddresses = StringUtils.replace(allowedRemoteAddresses, ";", ",");

        String[] allowedRemoteAddressesAsArray = StringUtils.commaDelimitedListToStringArray(allowedRemoteAddresses);

        List<Pattern> newAllowedRemoteAddresses = new ArrayList<Pattern>();
        for (String allowedRemoteAddress : allowedRemoteAddressesAsArray) {
            allowedRemoteAddress = StringUtils.trimWhitespace(allowedRemoteAddress);
            try {
                newAllowedRemoteAddresses.add(Pattern.compile(allowedRemoteAddress));
            } catch (PatternSyntaxException e) {
                throw new RuntimeException("Exception parsing allowedRemoteAddress '" + allowedRemoteAddress + "' for user '"
                        + this.getUsername() + "'", e);
            }
        }

        this.allowedRemoteAddresses = newAllowedRemoteAddresses;
    }

    public void setComments(String comments) {
        this.comments = comments;
    }

    @Override
    public String toString() {
        return super.toString() + "; allowedRemoteAddresses: " + this.allowedRemoteAddresses;
    }
}