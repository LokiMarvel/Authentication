package org.sign.authentication.security;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final Jwt jwt;
    private final AuthenticationManager authenticationManager;


    public AuthenticationResponse register(RegisterRequest request) {
        UserDetails user = User.builder()
                .userName(request.getUserName())
                .password(passwordEncoder.encode(request.getPassword()))
                .grantedAuthorities(Collections.singleton(new SimpleGrantedAuthority("ROLE_USER"))).build();
        userRepository.createUser(user);

        return AuthenticationResponse.builder()
                .jwtToken(jwt.generateToken(user)).build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUserName(),request.getPassword()));
        UserDetails user = userRepository.loadUserByUsername(request.getUserName());
        String jwtToken = jwt.generateToken(user);
        return AuthenticationResponse.builder()
                .jwtToken(jwtToken)
                .build();
    }
}
