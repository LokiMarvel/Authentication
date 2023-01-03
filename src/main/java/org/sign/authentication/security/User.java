package org.sign.authentication.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Set;

@Getter
@Setter
public class User implements UserDetails {


    private String userName;
    private String password;
    private boolean accountExpired;
    private boolean accountLocked;
    private boolean enabled;
    private boolean credentialsNonExpired;

    private Set<? extends GrantedAuthority> grantedAuthorities;


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return grantedAuthorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return userName;
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
