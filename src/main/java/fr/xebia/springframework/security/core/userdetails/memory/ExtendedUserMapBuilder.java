/*
 * Copyright 2010 Xebia and the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.xebia.springframework.security.core.userdetails.memory;

import fr.xebia.springframework.security.core.userdetails.ExtendedUser;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.memory.UserMap;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Provides utilities method to build a {@link org.springframework.security.core.userdetails.memory.UserMap} from user
 * definition.
 *
 * @author David Galichet
 */
// Suppress warning for deprecated UserMap until InMemoryDaoImpl will use it:
@SuppressWarnings("deprecation")
public class ExtendedUserMapBuilder {
    private static final String ENABLED = "enabled";
    private static final String DISABLED = "disabled";

    /**
     * Build {@link org.springframework.security.core.userdetails.memory.UserMap} from user attributes.
     * Attributes are defined by :
     * <code>username=password,grantedAuthority[,grantedAuthority][,enabled|disabled][,@(allowedIpAddresses)]</code>
     * @param userMap {@link org.springframework.security.core.userdetails.memory.UserMap} to populate.
     * @param usersAttributes {@link java.util.Properties} describing users and their attributes.
     * @return updated <code>userMap</code>.
     */
    public static UserMap buildUserMapFromProperties(UserMap userMap, Properties usersAttributes) {
        if (usersAttributes == null) {
            return userMap;
        }
        
        for (Map.Entry<Object, Object> entry : usersAttributes.entrySet()) {
            String userAttributes = entry.getKey() + "=" +  entry.getValue();
            UserDetails user = buildExtendedUser(userAttributes);
            if (user != null) {
                userMap.addUser(user);
            }
        }
        return userMap;
    }

    /**
     * Build an {@link fr.xebia.springframework.security.core.userdetails.ExtendedUser} from user attributes.
     * Protected for test purpose.
     * @param userAttributes a list.
     * @return the build {@link fr.xebia.springframework.security.core.userdetails.ExtendedUser}.
     */
    protected static ExtendedUser buildExtendedUser(String userAttributes) {
        if (userAttributes == null) {
            return null;
        }

        String[] userAttributesStringArray = StringUtils.delimitedListToStringArray(userAttributes, "=");

        if (userAttributesStringArray.length != 2) {
            return null; // we need a username and some attributes.
        }
        String username = userAttributesStringArray[0].trim();

        Pattern pattern = Pattern.compile("(enabled|disabled){1}$");
        Matcher matcher = pattern.matcher(userAttributesStringArray[1].trim());

        // Check activated attribute
        boolean activated = true;
        if (matcher.find()) {
            activated = ENABLED.equals(matcher.group());
        }

        // Check authorized IP addresses
        String allowedIpAddresses = "";
        pattern = Pattern.compile("@\\(.*\\)");
        matcher = pattern.matcher(userAttributesStringArray[1]);
        if (matcher.find()) {
            allowedIpAddresses = StringUtils.deleteAny(matcher.group(), "@() ");
        }

        // Get user password and roles :
        pattern = Pattern.compile("((,\\ *@\\(.*\\)){0,1}(\\ *,\\ *(enabled|disabled)\\ *){0,1})$");
        String[] remainingAttributes = pattern.split(userAttributesStringArray[1]);
        if (remainingAttributes.length != 1) {
            return null; // password and role(s) must have been defined.
        }

        String[] attributes = StringUtils.commaDelimitedListToStringArray(remainingAttributes[0]);
        if (attributes.length < 2) {
            return null; // we need at least one password and one role.
        }
        String password = attributes[0].trim();
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        for (int i = 1; i < attributes.length; i++) {
            authorities.add(new GrantedAuthorityImpl(attributes[i].trim()));
        }

        ExtendedUser extendedUser = new ExtendedUser(username, password, activated, true, true, true, authorities);
        extendedUser.setAllowedRemoteAddresses(allowedIpAddresses);
        return extendedUser;
    }
}
