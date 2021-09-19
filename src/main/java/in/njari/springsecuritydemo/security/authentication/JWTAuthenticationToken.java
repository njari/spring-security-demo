package in.njari.springsecuritydemo.security.authentication;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

public class JWTAuthenticationToken extends UsernamePasswordAuthenticationToken {

    public JWTAuthenticationToken(Object principal, Object credentials) {
        super(principal, credentials);
    }
}
