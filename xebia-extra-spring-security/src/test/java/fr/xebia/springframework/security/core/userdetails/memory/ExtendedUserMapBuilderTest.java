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
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.memory.UserMap;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.StringTokenizer;

import static org.junit.Assert.*;

/**
 * @author David Galichet.
 */
public class ExtendedUserMapBuilderTest {


    public static final String ROLES0 = "ROLE";
    public static final String ROLES1 = "ROLE, ROLE_USER";

    public static final String ENABLED = "enabled";
    public static final String DISABLED = "disabled";

    public static final String IP0 = "192.168.1.*";
    public static final String IP1 = "127.0.0.1;192.168.1.*";

    public static final String TEMPLATE_TC0 = "bob=password,%s";
    public static final String TEMPLATE_TC1 = "bob=password,%s,%s";
    public static final String TEMPLATE_TC2 = "bob=password,%s,%s,@(%s)";
    public static final String TEMPLATE_TC3 = "bob=password,%s,@(%s)";
    public static final String TEMPLATE_TC4 = "bob = password  , %s, %s,@( %s )";

    public static final String[][] TC0 = {{TEMPLATE_TC2, ROLES1, ENABLED, IP1}, //bob=password,ROLE_USER, ROLE_ADMIN,enabled,@(127.0.0.1;192.168.1.*)
            {TEMPLATE_TC3, ROLES1, ENABLED, IP1}, //bob=password,ROLE_USER, ROLE_ADMIN, @(127.0.0.1;192.168.1.*)
            {TEMPLATE_TC0, ROLES1, ENABLED, ""}, //bob=password,ROLE_USER, ROLE_ADMIN
            {TEMPLATE_TC2, ROLES1, DISABLED, IP1}, //bob=password,ROLE_USER,ROLE_ADMIN,disabled, @(127.0.0.1;192.168.1.*)
            {TEMPLATE_TC1, ROLES1, DISABLED, ""}, //bob=password,ROLE_USER,ROLE_ADMIN,disabled
            {TEMPLATE_TC4, ROLES0, DISABLED, IP0} //bob = password ,ROLE_USER ,  disabled , @( 127.0.0.1)
    };


    @Before
    public void setUp() throws Exception { }

    @Test
    public void testAddUsersFromBadProperties() throws Exception {
        Properties properties = new Properties();
        properties.setProperty("bob", ""); // at least password is mandatory so it will fail
        UserMap userMap = new UserMap();
        userMap = ExtendedUserMapBuilder.buildUserMapFromProperties(userMap, properties);
        assertEquals("Unexpected entry", 0, userMap.getUserCount());
    }

    @Test
    public void testAddUsersFromNullProperties() throws Exception {
        UserMap userMap = new UserMap();
        userMap = ExtendedUserMapBuilder.buildUserMapFromProperties(userMap, null);
        assertEquals("Unexpected entry", 0, userMap.getUserCount());
    }

    @Test
    public void testAddUsersFromProperties() throws Exception {
        final String USER1 = "bob";
        final String PROP1 = "bobpassword,ROLE,USER_ROLE,enabled,@(192.168.1.*;127.0.0.1)";
        final String USER2 = "bill";
        final String PROP2 = "billpassword,USER_ROLE,disabled,@(127.0.0.1)";

        Properties properties = new Properties();
        properties.setProperty(USER1, PROP1);
        properties.setProperty(USER2, PROP2);
        UserMap userMap = new UserMap();
        userMap = ExtendedUserMapBuilder.buildUserMapFromProperties(userMap, properties);
        assertEquals("Unexpected number of users", 2, userMap.getUserCount());
        assertNotNull("Unable to find user name", userMap.getUser(USER1));
        assertTrue("Bad activated parameter", userMap.getUser(USER1).isEnabled());
        assertNotNull("Unable to find user name", userMap.getUser(USER2));
        assertFalse("Bad activated parameter", userMap.getUser(USER2).isEnabled());
    }

    @Test
    public void testExtractBadlyDefinedUser() {
        assertNull(ExtendedUserMapBuilder.buildExtendedUser(null));
        assertNull(ExtendedUserMapBuilder.buildExtendedUser("bad properties"));
    }

    @Test
    public void testExtractExtendedUser() throws Exception {

        for (int i = 0; i < TC0.length; i++) {
            List<String> authorities = new ArrayList<String>();
            StringTokenizer tokenizer = new StringTokenizer(TC0[i][1], ",");
            while (tokenizer.hasMoreTokens()) {
                authorities.add(tokenizer.nextToken().trim());
            }

            String properties = assembleTestCases(TC0[i]);
            ExtendedUser user = ExtendedUserMapBuilder.buildExtendedUser(properties);
            assertNotNull(String.format("user is null (%s)", properties), user);
            assertEquals(String.format("username incorrect (%s)", properties), "bob", user.getUsername());
            assertEquals(String.format("password incorrect (%s)", properties), "password", user.getPassword());
            assertEquals(String.format("enabled parameter incorrect (%s)", properties), !DISABLED.equals(TC0[i][2]), user.isEnabled());
            assertEquals(String.format("incorrect number of authorities (%s)", properties), authorities.size(), user.getAuthorities().size());
            for (GrantedAuthority authority : user.getAuthorities()) {
                assertTrue(String.format("unexpected authority (%s) : %s", properties, authority.getAuthority()),
                        authorities.contains(authority.getAuthority()));
            }
            assertEquals(String.format("IP addresses incorrect (%s)", properties), TC0[i][3].replace(';', ','), user.getAllowedRemoteAddresses());
        }
    }

    private static String assembleTestCases(String[] tcParameters) {
        if (tcParameters.length != 4)
            return "";

        if (TEMPLATE_TC0.equals(tcParameters[0]))
            return String.format(tcParameters[0], tcParameters[1]);
        if (TEMPLATE_TC1.equals(tcParameters[0]))
            return String.format(tcParameters[0], tcParameters[1], tcParameters[2]);
        if (TEMPLATE_TC2.equals(tcParameters[0]))
            return String.format(tcParameters[0], tcParameters[1], tcParameters[2], tcParameters[3]);
        if (TEMPLATE_TC3.equals(tcParameters[0]))
            return String.format(tcParameters[0], tcParameters[1], tcParameters[3]);
        if (TEMPLATE_TC4.equals(tcParameters[0]))
            return String.format(tcParameters[0], tcParameters[1], tcParameters[2], tcParameters[3]);
        return "";
    }
}
