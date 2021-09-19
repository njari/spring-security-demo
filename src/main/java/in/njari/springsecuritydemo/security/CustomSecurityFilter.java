package in.njari.springsecuritydemo.security;

import in.njari.springsecuritydemo.security.authentication.AuthUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

@Component
public class CustomSecurityFilter extends OncePerRequestFilter {

    @Autowired
    AuthUtil authUtil;
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {

        String bearerToken = httpServletRequest.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            bearerToken = bearerToken.substring(7);
        }

        try {
            if (bearerToken != null ) {
                Optional<Authentication> auth = authUtil.createAuthentication(bearerToken);

                if (auth.isEmpty()) {
                    /**
                     * Exception can be more descriptive when using in a real application.
                     */
                    throw new Exception("Access denied.");
                }
                /**
                 * Adding user's data to the security context to access later in the business logic
                 */

                SecurityContextHolder.getContext().setAuthentication(auth.get());
            }
            else {
                String username = httpServletRequest.getHeader("username");
                String password = httpServletRequest.getHeader("password");
                if (username != null && password != null) {
                    Optional<Authentication> auth = Optional.of(authUtil.createAuthentication(username, password));
                    if (!auth.isPresent()) {
                        throw new Exception("Access denied.");
                    }
                    SecurityContextHolder.getContext().setAuthentication(auth.get());
                }
            }

        } catch (Exception ex) {
            SecurityContextHolder.clearContext();
            httpServletResponse.sendError(HttpStatus.FORBIDDEN.value(),ex.getMessage());
            return;
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

}
