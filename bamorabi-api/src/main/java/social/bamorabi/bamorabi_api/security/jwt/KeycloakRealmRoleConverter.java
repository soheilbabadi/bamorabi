package social.bamorabi.bamorabi_api.security.jwt;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;

/**
 * Maps Keycloak roles found in a validated JWT to Spring Security authorities.
 *
 * <p>Roles are read exclusively from the cryptographically verified token — never from request
 * headers or parameters. Both standard Keycloak role locations are supported:</p>
 * <ul>
 *   <li>{@code realm_access.roles}</li>
 *   <li>{@code resource_access.<clientId>.roles} (only when a client id is configured)</li>
 * </ul>
 *
 * <p>Authorities follow the {@code ROLE_<NAME>} convention, for example a Keycloak role
 * {@code super_admin} becomes {@code ROLE_SUPER_ADMIN}.</p>
 */
public class KeycloakRealmRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private static final String ROLE_PREFIX = "ROLE_";

    private final String clientId;

    public KeycloakRealmRoleConverter(String clientId) {
        this.clientId = StringUtils.hasText(clientId) ? clientId : null;
    }

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Set<GrantedAuthority> authorities = new HashSet<>();
        collectRoles(jwt.getClaimAsMap("realm_access")).forEach(role -> authorities.add(toAuthority(role)));
        if (clientId != null) {
            Map<String, Object> resourceAccess = jwt.getClaimAsMap("resource_access");
            if (resourceAccess != null) {
                collectRoles(asMap(resourceAccess.get(clientId)))
                        .forEach(role -> authorities.add(toAuthority(role)));
            }
        }
        return authorities;
    }

    private static List<String> collectRoles(Map<String, Object> container) {
        if (container == null) {
            return List.of();
        }
        Object roles = container.get("roles");
        if (roles instanceof Collection<?> collection) {
            return collection.stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .toList();
        }
        return List.of();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value) {
        return value instanceof Map<?, ?> map ? (Map<String, Object>) map : null;
    }

    private static GrantedAuthority toAuthority(String role) {
        String normalized = role.toUpperCase().replace('-', '_');
        return new SimpleGrantedAuthority(normalized.startsWith(ROLE_PREFIX) ? normalized : ROLE_PREFIX + normalized);
    }
}
