package social.bamorabi.bamorabi_api.security.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Type-safe configuration describing how Keycloak-issued JWTs are interpreted.
 *
 * <p>The token issuer itself is configured through the standard Spring Boot property
 * {@code spring.security.oauth2.resourceserver.jwt.issuer-uri}; these properties only add the
 * Keycloak-specific mapping information that Spring Security cannot infer on its own.</p>
 */
@ConfigurationProperties(prefix = "app.security.keycloak")
public record KeycloakJwtProperties(
        /**
         * Keycloak client whose {@code resource_access.<clientId>.roles} are mapped to authorities.
         * Leave empty when roles are only published as realm roles.
         */
        @DefaultValue("") String clientId,
        /**
         * Name of a trusted tenant claim (for example {@code tenant_id}) copied into the principal.
         * Empty by default: tenant membership is never assumed and arbitrary request headers are
         * not trusted. Tenant authorization is handled by a dedicated layer in a later step.
         */
        @DefaultValue("") String tenantClaim) {
}
