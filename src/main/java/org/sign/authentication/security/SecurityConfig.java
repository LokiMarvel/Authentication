package org.sign.authentication.security;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Collections;

@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig {

    @Autowired
    private UserService userService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }

    @Bean
    @SneakyThrows
    public SecurityFilterChain filterChain(HttpSecurity http) {
        return http
                .csrf()
                .disable()
                .httpBasic()
                .and()
                .authorizeHttpRequests()
                .anyRequest()
                .authenticated()
                .and().build();
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        daoAuthenticationProvider.setUserDetailsService(userService);
        return daoAuthenticationProvider;
    }

    @Bean
    public ApplicationRunner applicationRunner(UserService service) {
        return args -> {
            User user = new User();
            user.setUserName("sai");
            user.setPassword(passwordEncoder().encode("sai"));
            user.setEnabled(true);
            user.setAccountLocked(false);
            user.setAccountExpired(false);
            user.setCredentialsNonExpired(true);
            user.setGrantedAuthorities(Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
            service.createUser(user);
            log.info(String.format("%s Created Successfully",user.getUsername()));

            user.setUserName("praveen");
            user.setPassword(passwordEncoder().encode("praveen"));
            user.setEnabled(true);
            user.setAccountLocked(false);
            user.setAccountExpired(false);
            user.setCredentialsNonExpired(true);
            user.setGrantedAuthorities(Collections.singleton(new SimpleGrantedAuthority("ROLE_ADMIN")));
            service.createUser(user);
            log.info(String.format("%s is created successfully.",user.getUsername()));
        };
    }
}
