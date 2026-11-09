package social.bamorabi.bamorabi_api.security.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Type-safe configuration for the application's CORS policy.
 *
 * <p>All values are supplied through {@code app.security.cors.*} application properties so that
 * no origin, method or header is ever hardcoded in Java. Credentials are supported only with
 * explicit origins (never with a wildcard), as required by the CORS specification.</p>
 */
@ConfigurationProperties(prefix = "app.security.cors")
public record CorsProperties(
        @DefaultValue({"http://localhost:3000"}) List<String> allowedOrigins,
        @DefaultValue({"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}) List<String> allowedMethods,
        @DefaultValue({"Authorization", "Content-Type", "Accept"}) List<String> allowedHeaders,
        @DefaultValue("Authorization") List<String> exposedHeaders,
        @DefaultValue("true") boolean allowCredentials,
        @DefaultValue("3600") long maxAge) {

    public CorsProperties {
        allowedOrigins = List.copyOf(allowedOrigins);
        allowedMethods = List.copyOf(allowedMethods);
        allowedHeaders = List.copyOf(allowedHeaders);
        exposedHeaders = List.copyOf(exposedHeaders);
    }
}
