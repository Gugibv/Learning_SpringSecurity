package com.grey.integration.demo.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableConfigurationProperties(SecurityConfig.SecurityProps.class)
public class SecurityConfig {

    private final SecurityProps props;

    public SecurityConfig(SecurityProps props) {
        this.props = props;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           ClientRegistrationRepository clientRepo) throws Exception {

        // Spring 默认解析器（生成标准 authorization_request）
        DefaultOAuth2AuthorizationRequestResolver delegate =
                new DefaultOAuth2AuthorizationRequestResolver(clientRepo, "/oauth2/authorization");

        // ➜ 包装一个自定义解析器，修改 state / nonce，确保不含分号
        OAuth2AuthorizationRequestResolver customResolver = new OAuth2AuthorizationRequestResolver() {
            @Override
            public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
                return customize(delegate.resolve(request));
            }

            @Override
            public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientId) {
                return customize(delegate.resolve(request, clientId));
            }

            private OAuth2AuthorizationRequest customize(OAuth2AuthorizationRequest orig) {
                if (orig == null) return null;
                return OAuth2AuthorizationRequest.from(orig)
                        .state(UUID.randomUUID().toString().replaceAll("[;=]", ""))   // 干净的 state
                        .attributes(attrs -> attrs.put("nonce", UUID.randomUUID().toString()))
                        .build();
            }
        };

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(props.getWhitelist().toArray(String[]::new)).permitAll()
                        .anyRequest().authenticated()
                )
                .logout(logout -> logout.logoutSuccessUrl("/"))
                .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(ep -> ep.authorizationRequestResolver(customResolver))
                )
                .oauth2ResourceServer(rs -> rs.jwt(Customizer.withDefaults()));


        return http.build();
    }

    /* ---------- YAML 白名单绑定 ---------- */
    @ConfigurationProperties(prefix = "app.security")
    public static class SecurityProps {
        private List<String> whitelist = new ArrayList<>();
        public List<String> getWhitelist() { return whitelist; }
        public void setWhitelist(List<String> whitelist) { this.whitelist = whitelist; }
    }
}
