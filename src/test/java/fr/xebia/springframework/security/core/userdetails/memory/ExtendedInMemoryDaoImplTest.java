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

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.userdetails.memory.InMemoryDaoImpl;
import org.springframework.security.core.userdetails.memory.UserMap;

import java.util.Properties;

import static org.junit.Assert.*;

/**
 * @author David Galichet
 */
/**
 * Suppress deprecation warning on {@link UserMap} because {@link InMemoryDaoImpl} also
 * suppress warnings on deprecation.
 */
@SuppressWarnings("deprecation")
public class ExtendedInMemoryDaoImplTest {

    @Before
    public void setUp() throws Exception {
    }

    @Test
    public void testSetUserNullProperties() {
        ExtendedInMemoryDaoImpl dao = new ExtendedInMemoryDaoImpl();
        dao.setUserProperties(null);
        assertEquals("Unexpected user", 0, dao.getUserMap().getUserCount());
    }

    @Test
    public void testSetUserBadProperties() {
        ExtendedInMemoryDaoImpl dao = new ExtendedInMemoryDaoImpl();
        Properties properties = new Properties();
        properties.setProperty("bill", ""); // at least password is mandatory so
                                            // it will fail
        dao.setUserProperties(properties);
        assertEquals("Unexpected user", 0, dao.getUserMap().getUserCount());
    }

    @Test
    public void testSetUserProperties() {
        final String USER1 = "bob";
        final String PROP1 = "bobpassword,ROLE,USER_ROLE,enabled,@(192.168.1.*;127.0.0.1)";

        ExtendedInMemoryDaoImpl dao = new ExtendedInMemoryDaoImpl();
        Properties properties = new Properties();
        properties.setProperty(USER1, PROP1);
        dao.setUserProperties(properties);
        assertEquals("Unexpected number of users", 1, dao.getUserMap().getUserCount());
        assertNotNull("Unable to find user name", dao.getUserMap().getUser(USER1));
        assertTrue("Bad activated parameter", dao.getUserMap().getUser(USER1).isEnabled());
    }

}
