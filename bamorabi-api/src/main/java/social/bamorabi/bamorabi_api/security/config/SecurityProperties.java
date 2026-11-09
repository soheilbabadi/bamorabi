package social.bamorabi.bamorabi_api.security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Type-safe configuration listing the endpoints that are reachable without authentication.
 *
 * <p>Everything not matched by these patterns requires a valid Keycloak JWT. Business-specific
 * authorization rules are intentionally out of scope at this stage.</p>
 */
@ConfigurationProperties(prefix = "app.security")
public record SecurityProperties(String[] publicPaths) {

    private static final String[] DEFAULT_PUBLIC_PATHS = {
            "/api/v1/public/**",
            "/actuator/health",
            "/actuator/health/**",
            "/swagger-ui/**",
            "/swagger-ui.html",
            "/v3/api-docs/**"
    };

    public SecurityProperties {
        publicPaths = (publicPaths == null || publicPaths.length == 0)
                ? DEFAULT_PUBLIC_PATHS.clone()
                : publicPaths.clone();
    }
}
