package org.sign.authentication.security;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@Slf4j
@RequiredArgsConstructor
public class SecurityConfig {


    private final UserService userService;
    private final JwtAuthFilter jwtAuthFilter;


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
                .authorizeHttpRequests()
                .requestMatchers("/api/authenticate/**")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .sessionManagement(session -> session.maximumSessions(1).maxSessionsPreventsLogin(true))
                .authenticationProvider(daoAuthenticationProvider())
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        daoAuthenticationProvider.setUserDetailsService(userService);
        return daoAuthenticationProvider;
    }

    @Bean
    @SneakyThrows
    public AuthenticationManager getauthenticationManager(AuthenticationConfiguration authenticationConfiguration) {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /*@Bean
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
    }*/
}
