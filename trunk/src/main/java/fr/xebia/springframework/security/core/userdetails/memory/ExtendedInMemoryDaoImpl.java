
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

import org.springframework.security.core.userdetails.memory.InMemoryDaoImpl;
import org.springframework.security.core.userdetails.memory.UserMap;

import java.util.Properties;


/**
 * Extension of the {@link org.springframework.security.core.userdetails.memory.InMemoryDaoImpl} to add support for
 * allowed IP address definition.<br/>
 *
 * This implementation of {@link org.springframework.security.core.userdetails.UserDetailsService} must be used with
 * the {@link fr.xebia.springframework.security.core.providers.ExtendedDaoAuthenticationProvider}.
 *
 * <p>The users will be defined as :
 * <code>username=password,grantedAuthority[,grantedAuthority][,enabled|disabled][,@(allowedIpAddress)]</code></p>
 * <p>The <code>allowedIpAddress</code> is a semicolon separated list of IP address schemes.<br/>
 * For example : <code>bob:bobpassword,ROLE,USER_ROLE,enabled,@(192.168.1.*;127.0.0.1)</code></p>
 *
 * @see fr.xebia.springframework.security.core.userdetails.ExtendedUser
 * @author David Galichet.
 */
// Suppress warning for deprecated UserMap until InMemoryDaoImpl will use it:
@SuppressWarnings("deprecation")
public class ExtendedInMemoryDaoImpl extends InMemoryDaoImpl {

    /**
     * Extend {@link org.springframework.security.core.userdetails.memory.InMemoryDaoImpl} to add support for allowed IP address.
     * @param properties the account information in a <code>Properties</code> object format
     */
    @Override
    public void setUserProperties(Properties properties) {
        UserMap extendedUserMap = new UserMap();
        extendedUserMap = ExtendedUserMapBuilder.buildUserMapFromProperties(extendedUserMap, properties);
        if (extendedUserMap != null) {
            setUserMap(extendedUserMap);
        } else {
            setUserMap(new UserMap());
        }
    }
}
