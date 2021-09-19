package in.njari.springsecuritydemo.security.authentication.provider;

import in.njari.springsecuritydemo.security.CustomUserDetails;
import in.njari.springsecuritydemo.security.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
@Component
public class UsernamePasswordAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    CustomUserDetailsService customUserDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = String.valueOf(authentication.getCredentials());

        CustomUserDetails customUserDetails = customUserDetailsService.loadUserByUsername(username);
        if (customUserDetails!=null) {
            if (password.equals(customUserDetails.getPassword())) {
                return new UsernamePasswordAuthenticationToken(
                        customUserDetails, "", new ArrayList<>());
            }
        }
        return null;
    }

    @Override
    public boolean supports(Class<?> auth) {
        return auth.equals(UsernamePasswordAuthenticationToken.class);
    }

}
