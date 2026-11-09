package social.bamorabi.bamorabi_api.security.jwt;

import java.util.Collection;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.util.StringUtils;

/**
 * Converts a fully validated {@link org.springframework.security.oauth2.jwt.Jwt} into a
 * {@link JwtAuthenticationToken} whose principal is a {@link JwtPrincipal}.
 *
 * <p>This class performs no JWT validation whatsoever; it runs only after the {@code JwtDecoder}
 * has verified signature, expiry, issuer and audience. Its single responsibility is translating
 * trusted claims into the application's principal abstraction and authority set.</p>
 */
public class KeycloakJwtAuthenticationConverter
        implements Converter<org.springframework.security.oauth2.jwt.Jwt, JwtAuthenticationToken> {

    private final KeycloakRealmRoleConverter roleConverter;
    private final String tenantClaim;

    public KeycloakJwtAuthenticationConverter(KeycloakJwtProperties properties) {
        this.roleConverter = new KeycloakRealmRoleConverter(properties.clientId());
        this.tenantClaim = StringUtils.hasText(properties.tenantClaim()) ? properties.tenantClaim() : null;
    }

    @Override
    public JwtAuthenticationToken convert(org.springframework.security.oauth2.jwt.Jwt jwt) {
        Collection<GrantedAuthority> authorities = roleConverter.convert(jwt);
        String tenantId = tenantClaim != null ? jwt.getClaimAsString(tenantClaim) : null;
        JwtPrincipal principal = new JwtPrincipal(jwt, authorities, tenantId);
        return new JwtAuthenticationToken(jwt, principal, authorities);
    }
}
