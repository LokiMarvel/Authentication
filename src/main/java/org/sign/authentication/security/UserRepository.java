package org.sign.authentication.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.stereotype.Repository;

import javax.sql.DataSource;

@Repository
public class UserRepository extends JdbcUserDetailsManager {
    @Autowired
    public UserRepository(DataSource dataSource) {
        setDataSource(dataSource);
    }
}
