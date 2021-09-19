package in.njari.springsecuritydemo.security.authentication.provider;

import in.njari.springsecuritydemo.security.authentication.JWTAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;

@Component
public class JWTAuthenticationProvider implements AuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        return new UsernamePasswordAuthenticationToken(
                authentication.getPrincipal(), "", new ArrayList<>());
        }

        @Override
        public boolean supports(Class<?> auth) {
            return auth.equals(JWTAuthenticationToken.class);
        }

}
