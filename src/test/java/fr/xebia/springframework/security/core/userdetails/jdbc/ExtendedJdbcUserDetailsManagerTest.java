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
package fr.xebia.springframework.security.core.userdetails.jdbc;

import static org.junit.Assert.assertEquals;

import java.sql.Connection;
import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.core.simple.SimpleJdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.jdbc.SimpleJdbcTestUtils;

import fr.xebia.springframework.security.core.userdetails.ExtendedUser;

public class ExtendedJdbcUserDetailsManagerTest {

    protected ExtendedJdbcUserDetailsManager userDetailsManager;

    protected SimpleJdbcTemplate simpleJdbcTemplate;

    @Before
    public void before() throws Exception {
        SingleConnectionDataSource dataSource = new SingleConnectionDataSource("jdbc:h2:mem:jmx-demo-db", "sa", "", false);

        Connection connection = dataSource.getConnection();
        String createUsersTable = "create table users(username varchar(256), password varchar(256), enabled int, allowedRemoteAddresses varchar(256), comments varchar(256))";
        connection.createStatement().execute(createUsersTable);

        String createAuthoritiesTable = "create table authorities(username varchar(256), authority varchar(256))";
        connection.createStatement().execute(createAuthoritiesTable);

        userDetailsManager = new ExtendedJdbcUserDetailsManager();

        userDetailsManager.setDataSource(dataSource);
        simpleJdbcTemplate = new SimpleJdbcTemplate(dataSource);

    }

    @Test
    public void testCreateUpdateDeleteUserUserDetails() throws Exception {
        // CREATE
        {
            // PREPARE
            List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
            authorities.add(new GrantedAuthorityImpl("ROLE_USER"));
            authorities.add(new GrantedAuthorityImpl("ROLE_ADMIN"));

            ExtendedUser user = new ExtendedUser("test-user", "test-password", true, true, true, true, authorities);
            user.setComments("my first comment");
            user.setAllowedRemoteAddresses("10\\..*");

            // CREATE USER
            userDetailsManager.createUser(user);

            // VERIFY
            assertEquals(1, SimpleJdbcTestUtils.countRowsInTable(simpleJdbcTemplate, "users"));
            assertEquals(2, SimpleJdbcTestUtils.countRowsInTable(simpleJdbcTemplate, "authorities"));
        }

        // LOAD AND UPDATE
        {

            // LOAD USER
            UserDetails userDetails = userDetailsManager.loadUserByUsername("test-user");
            ExtendedUser actualExtendedUser = (ExtendedUser) userDetails;

            // VERIFY
            assertEquals("test-user", actualExtendedUser.getUsername());
            assertEquals("test-password", actualExtendedUser.getPassword());
            assertEquals("10\\..*", actualExtendedUser.getAllowedRemoteAddresses());
            assertEquals(2, actualExtendedUser.getAuthorities().size());

            // UPDATE USER
            actualExtendedUser.setComments("updated comment");
            userDetailsManager.updateUser(actualExtendedUser);

            // RELOAD USER
            ExtendedUser updatedUser = (ExtendedUser) userDetailsManager.loadUserByUsername("test-user");

            // VERIFY
            assertEquals("updated comment", updatedUser.getComments());
        }

        // DELETE
        {
            userDetailsManager.deleteUser("test-user");
            // VERIFY
            assertEquals(0, SimpleJdbcTestUtils.countRowsInTable(simpleJdbcTemplate, "users"));
            assertEquals(0, SimpleJdbcTestUtils.countRowsInTable(simpleJdbcTemplate, "authorities"));
        }

    }

}
