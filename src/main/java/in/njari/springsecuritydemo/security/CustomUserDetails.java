package in.njari.springsecuritydemo.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

public class CustomUserDetails implements UserDetails {

    String username;
    String userTagline;
    String password;

    public CustomUserDetails(String username, String userTagline) {
        this.username = username;
        this.userTagline = userTagline;
        this.password = null;
    }

    public CustomUserDetails(String username, String userTagline, String password) {
        this.username = username;
        this.userTagline = userTagline;
        this.password = password;
    }
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    public String getUserTagline() {
        return this.userTagline;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
