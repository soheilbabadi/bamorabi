package social.bamorabi.bamorabi_api.security.support;

import java.util.Optional;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import social.bamorabi.bamorabi_api.security.jwt.JwtPrincipal;

/**
 * Read-only accessor for the authenticated application identity of the current request.
 *
 * <p>Business code uses this component instead of touching {@code SecurityContextHolder} directly.
 * It performs no authentication work itself; it only reads what the security filter chain has
 * already established.</p>
 */
@Component
public class CurrentUser {

    /** The authenticated {@link JwtPrincipal}, or empty when the request is unauthenticated. */
    public Optional<JwtPrincipal> find() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuthenticationToken token
                && token.getToken() != null
                && token.getPrincipal() instanceof JwtPrincipal principal) {
            return Optional.of(principal);
        }
        return Optional.empty();
    }

    /**
     * The authenticated principal.
     *
     * @throws IllegalStateException when called outside an authenticated request
     */
    public JwtPrincipal require() {
        return find().orElseThrow(() ->
                new IllegalStateException("No authenticated principal available for the current request"));
    }
}
