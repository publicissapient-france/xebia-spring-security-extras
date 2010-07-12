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

import fr.xebia.springframework.security.core.userdetails.ExtendedUser;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

/**
 * Extension of the {@link org.springframework.security.provisioning.JdbcUserDetailsManager} to add the '
 * <code>allowedRemoteAddresses</code>' (<code>varchar</code>) and '
 * <code>comments</code>' (<code>varchar</code>) columns in the '
 * <code>users</code>' table.
 *
 * @author <a href="mailto:cyrille@cyrilleleclerc.com">Cyrille Le Clerc</a>
 */
public class ExtendedJdbcUserDetailsManager extends JdbcUserDetailsManager implements UserDetailsManager {

    protected final Log log = LogFactory.getLog(getClass());

    private String selectUserExtraColumns = "SELECT allowedRemoteAddresses, comments FROM users WHERE username = ?";

    private String updateUserExtraColumns = "UPDATE users set allowedRemoteAddresses= ?, comments= ? WHERE username = ?";

    /**
     * Update {@link fr.xebia.springframework.security.core.userdetails.ExtendedUser} extra columns in addition to the behavior of
     * {@link org.springframework.security.provisioning.JdbcUserDetailsManager#createUser(org.springframework.security.core.userdetails.UserDetails).}
     */
    @Override
    public void createUser(UserDetails user) {
        super.createUser(user);
        updateUserExtraColumns(user);
    }

    @Override
    protected UserDetails createUserDetails(String username, UserDetails userFromUserQuery, List<GrantedAuthority> combinedAuthorities) {
        final User user = (User) super.createUserDetails(username, userFromUserQuery, combinedAuthorities);
        List<UserDetails> users = getJdbcTemplate().query(selectUserExtraColumns, new String[] { username }, new RowMapper<UserDetails>() {
            public UserDetails mapRow(ResultSet rs, int rowNum) throws SQLException {
                ExtendedUser extendedUser = new ExtendedUser(user.getUsername(), user.getPassword(), user.isEnabled(), user
                        .isAccountNonExpired(), user.isCredentialsNonExpired(), user.isAccountNonLocked(), user.getAuthorities());
                extendedUser.setAllowedRemoteAddresses(rs.getString(1));
                extendedUser.setComments(rs.getString(2));

                return extendedUser;
            }
        });
        if (users.size() == 0) {
            throw new UsernameNotFoundException(messages.getMessage("JdbcDaoImpl.notFound", new Object[] { username },
                    "Username {0} not found"), username);
        }
        return users.get(0);
    }

    public String getSelectUserExtraColumns() {
        return selectUserExtraColumns;
    }

    public String getUpdateUserExtraColumns() {
        return updateUserExtraColumns;
    }

    public void setSelectUserExtraColumns(String selectUserExtraColumns) {
        this.selectUserExtraColumns = selectUserExtraColumns;
    }

    public void setUpdateUserExtraColumns(String updateUserExtraColumns) {
        this.updateUserExtraColumns = updateUserExtraColumns;
    }

    /**
     * Update {@link fr.xebia.springframework.security.core.userdetails.ExtendedUser} extra columns in addition to the behavior of
     * {@link org.springframework.security.provisioning.JdbcUserDetailsManager#updateUser(org.springframework.security.core.userdetails.UserDetails).}
     */
    @Override
    public void updateUser(UserDetails user) {
        super.updateUser(user);
        updateUserExtraColumns(user);
    }

    /**
     * Update {@link fr.xebia.springframework.security.core.userdetails.ExtendedUser} extra columns associated with
     * {@link fr.xebia.springframework.security.core.userdetails.ExtendedUser#getAllowedRemoteAddresses()} and
     * {@link fr.xebia.springframework.security.core.userdetails.ExtendedUser#getComments()}.
     *
     * @param user
     */
    protected void updateUserExtraColumns(UserDetails user) {
        if (user instanceof ExtendedUser) {
            final ExtendedUser extendedUser = (ExtendedUser) user;
            int updatedRows = getJdbcTemplate().update(updateUserExtraColumns, new PreparedStatementSetter() {
                public void setValues(PreparedStatement ps) throws SQLException {
                    ps.setString(1, extendedUser.getAllowedRemoteAddresses());
                    ps.setString(2, extendedUser.getComments());
                    ps.setString(3, extendedUser.getUsername());
                }
            });
            if (updatedRows != 1) {
                log.warn("More/less (" + updatedRows + ") than one row have been updated modifying 'allowedRemoteIpAddresses' to '"
                        + extendedUser.getAllowedRemoteAddresses() + "' and 'comments' to '" + extendedUser.getComments()
                        + "' for username '" + extendedUser.getUsername() + "'");
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Given user " + user + " is not an ExtendedUser, no additional column to update.");
            }
        }
    }
}