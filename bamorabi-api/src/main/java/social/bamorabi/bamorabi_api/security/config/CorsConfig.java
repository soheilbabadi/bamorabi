package social.bamorabi.bamorabi_api.security.config;

import org.springframework.boot.autoconfigure.web.servlet.WebMvcProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Central, single source of CORS configuration for the whole application.
 *
 * <p>The resulting {@link CorsConfigurationSource} is consumed exclusively by Spring Security's
 * {@code CorsFilter} (see {@link SecurityConfig}); no other CORS mechanism (MVC global config,
 * {@code @CrossOrigin}, servlet filters) is enabled anywhere else, which avoids duplicate
 * {@code Access-Control-*} headers. Preflight {@code OPTIONS} requests are handled before the
 * authorization check, so they succeed even on protected endpoints.</p>
 */
@Configuration(proxyBeanMethods = false)
public class CorsConfig {

    @Bean
    CorsConfigurationSource corsConfigurationSource(CorsProperties properties, WebMvcProperties webMvcProperties) {
        if (properties.allowCredentials()) {
            // The CORS specification forbids credentialed requests against wildcard origins.
            properties.allowedOrigins().forEach(origin -> {
                if (origin.contains("*")) {
                    throw new IllegalStateException(
                            "CORS wildcard origins are not allowed when credentials are enabled: " + origin);
                }
            });
        }

        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(properties.allowedOrigins());
        configuration.setAllowedMethods(properties.allowedMethods());
        configuration.setAllowedHeaders(properties.allowedHeaders());
        configuration.setExposedHeaders(properties.exposedHeaders());
        configuration.setAllowCredentials(properties.allowCredentials());
        configuration.setMaxAge(properties.maxAge());

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration(servletPathPattern(webMvcProperties), configuration);
        return source;
    }

    private static String servletPathPattern(WebMvcProperties webMvcProperties) {
        String path = webMvcProperties.getServlet().getPath();
        return (path == null || path.isBlank() || "/".equals(path)) ? "/**" : path + "/**";
    }
}
