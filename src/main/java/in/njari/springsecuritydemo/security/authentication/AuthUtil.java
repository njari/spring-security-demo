package in.njari.springsecuritydemo.security.authentication;

import in.njari.springsecuritydemo.security.CustomUserDetails;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class AuthUtil {

    @Autowired
    AuthenticationManager authenticationManager;

    public static String secretKey = "my-really-ill-kept-secret";

    public Claims extractAllClaims(String token) {
        try {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody(); }
        catch (Exception e) {
            return null;
        }
    }


    /**
     * We authenticate our JWT token by simply validating that it was signed by us.
     */
    public Optional<Authentication> createAuthentication(String token) {

        Claims jwsClaims = extractAllClaims(token);
        if (jwsClaims == null) {
            return Optional.empty();
        }

        CustomUserDetails userDetails = new CustomUserDetails(
                jwsClaims.getSubject(),
                jwsClaims.get("userTagline", String.class)
        );

        return Optional.of(new JWTAuthenticationToken(userDetails, token));
    }

    /**
     * We now authenticate the password using a DAO call
     */
    public Authentication createAuthentication(String username, String password) {
        return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));

    }
}

