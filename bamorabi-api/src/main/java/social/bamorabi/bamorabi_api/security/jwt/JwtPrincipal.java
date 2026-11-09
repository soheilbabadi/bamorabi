package social.bamorabi.bamorabi_api.security.jwt;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * Authenticated principal built from a validated Keycloak JWT.
 *
 * <p>Wraps the already verified {@link Jwt} and exposes only identity claims that this application
 * considers trustworthy. It performs no validation of its own — signature, expiry, issuer and
 * audience checks have all been completed by the {@code JwtDecoder} before this object exists.</p>
 */
public class JwtPrincipal implements OAuth2User {

    private final Jwt jwt;
    private final Collection<GrantedAuthority> authorities;
    private final Map<String, Object> attributes;
    private final String tenantId;

    public JwtPrincipal(Jwt jwt, Collection<GrantedAuthority> authorities, String tenantId) {
        this.jwt = jwt;
        this.authorities = Collections.unmodifiableCollection(authorities);
        this.attributes = Collections.unmodifiableMap(jwt.getClaims());
        this.tenantId = tenantId;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        return authorities;
    }

    /** Keycloak user identifier ({@code sub} claim). */
    public String getId() {
        return jwt.getSubject();
    }

    /** Username reported by Keycloak, falling back to the subject when absent. */
    public String getUsername() {
        String preferredUsername = jwt.getClaimAsString("preferred_username");
        return (preferredUsername != null && !preferredUsername.isBlank())
                ? preferredUsername
                : jwt.getSubject();
    }

    public String getEmail() {
        return jwt.getClaimAsString("email");
    }

    public String getPreferredUsername() {
        return jwt.getClaimAsString("preferred_username");
    }

    /**
     * Tenant identifier taken from the explicitly configured, trusted tenant claim, or {@code null}
     * when no tenant claim is configured. Never derived from request headers.
     */
    public String getTenantId() {
        return tenantId;
    }

    /** Access to the underlying validated token for advanced, read-only use cases. */
    public Jwt getJwt() {
        return jwt;
    }

    @Override
    public String getName() {
        return getUsername();
    }

    @Override
    public String toString() {
        // Deliberately excludes claims and authorities so that tokens can never leak into logs.
        return "JwtPrincipal{subject='" + getId() + "'}";
    }
}
