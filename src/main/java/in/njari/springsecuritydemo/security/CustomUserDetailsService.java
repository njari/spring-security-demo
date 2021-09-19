package in.njari.springsecuritydemo.security;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class CustomUserDetailsService implements UserDetailsService {
    @Override
    public CustomUserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        /**
         * Here, you should access your repository and find your user.
         */
        if (s.equals("MyFirstUser")) {
            return new CustomUserDetails(s, "I'm happy to be authenticated!", "my-weak-weak-password");
        }
        throw new UsernameNotFoundException(s + " is not a valid user on the system.");
    }
}
