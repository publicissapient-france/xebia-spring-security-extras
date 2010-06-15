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

import java.util.*;

/** Provides utilities method to build a {@link org.springframework.security.core.userdetails.memory.UserMap} from user
 * definition.
 *
 * @author David Galichet
 */
public class ExtendedUserMapBuilder {
    private static final String ENABLED = "enabled";
    private static final String DISABLED = "disabled";

    /** Build {@link org.springframework.security.core.userdetails.memory.UserMap} from user attributes.
     * Attributes are defined by :
     * <code>username=password,grantedAuthority[,grantedAuthority][,enabled|disabled][,@(allowedIpAddress)]</code>
     * @param userMap {@link org.springframework.security.core.userdetails.memory.UserMap} to populate.
     * @param usersAttributes {@link java.util.Properties} describing users and their attributes.
     * @return updated <code>userMap</code>.
     */
    public static UserMap buildUserMapFromProperties(UserMap userMap, Properties usersAttributes) {
        if (usersAttributes == null)
            return userMap;
        
        for (Map.Entry<Object, Object> entry : usersAttributes.entrySet()) {
            String userAttributes = String.format("%s=%s", entry.getKey(), entry.getValue());
            UserDetails user = buildExtendedUser(userAttributes);
            if (user != null) {
                userMap.addUser(user);
            }
        }
        return userMap;
    }

    /** Build an {@link fr.xebia.springframework.security.core.userdetails.ExtendedUser} from user attributes.
     * Protected for test purpose.
     * @param userAttributes a list
     * @return
     */
    protected static ExtendedUser buildExtendedUser(String userAttributes) {
        if (userAttributes == null)
            return null;
        
        StringTokenizer tokenizer = new StringTokenizer(userAttributes, "=");
        if (tokenizer.countTokens() != 2)
            return null;
        String username = tokenizer.nextToken().trim();

        // Tokenize values of the properties
        tokenizer = new StringTokenizer(tokenizer.nextToken(),",");
        if (tokenizer.countTokens() < 1)
            return null; // we need at least a password

        // get password
        String password = tokenizer.nextToken().trim();

        boolean enabled = true;
        String ipAddress = "";

        // Iterate until we encounter activation parameter or IP address list.
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        while (tokenizer.hasMoreTokens()) {
            String token = tokenizer.nextToken().trim();
            if (ENABLED.equalsIgnoreCase(token)) {
                enabled = true;
            } else if (DISABLED.equalsIgnoreCase(token)) {
                enabled = false;
            } else if (token.startsWith("@(") && token.endsWith(")")) {
               ipAddress = token.substring(2, token.length() - 1);
            } else {
                authorities.add(new GrantedAuthorityImpl(token));
            }
        }
        ExtendedUser extendedUser = new ExtendedUser(username, password, enabled, true, true, true, authorities);
        extendedUser.setAllowedRemoteAddresses(ipAddress);
        return extendedUser;
    }
}
