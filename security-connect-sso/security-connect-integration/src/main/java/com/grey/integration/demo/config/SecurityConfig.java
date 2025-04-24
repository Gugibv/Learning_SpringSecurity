package com.grey.integration.demo.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;

import java.io.IOException;
import java.util.UUID;

@Configuration
public class SecurityConfig {

    public static class MyAuthenticationEntryPoint implements AuthenticationEntryPoint {

        private final RedirectStrategy redirectStrategy = new org.springframework.security.web.DefaultRedirectStrategy();
        private final String redirectUrl;

        public MyAuthenticationEntryPoint(String redirectUrl) {
            this.redirectUrl = redirectUrl;
        }

        @Override
        public void commence(HttpServletRequest request,
                             HttpServletResponse response,
                             org.springframework.security.core.AuthenticationException authException)
                throws IOException {

            // 直接 302 跳转到指定地址
            redirectStrategy.sendRedirect(request, response, redirectUrl);
        }
    }

    @Bean
    public MyAuthenticationEntryPoint myAuthenticationEntryPoint() {
        return new MyAuthenticationEntryPoint(
                "https://cls.loc.lhubsg.com:8080/oauth2/authorization/lhubsso");
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           ClientRegistrationRepository clientRepo) throws Exception {

        DefaultOAuth2AuthorizationRequestResolver delegate =
                new DefaultOAuth2AuthorizationRequestResolver(clientRepo, "/oauth2/authorization");

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
                        .state(UUID.randomUUID().toString().replaceAll("[;=]", ""))
                        .attributes(attrs -> attrs.put("nonce", UUID.randomUUID().toString()))
                        .build();
            }
        };

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/favicon.ico", "/api/sg/wb/v1/common/oidc/callback").permitAll()
                        .anyRequest().authenticated()
                )
                .logout(logout -> logout.logoutSuccessUrl("/"))
                .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(ep -> ep.authorizationRequestResolver(customResolver))
                        .redirectionEndpoint(redir -> redir.baseUri("/no-match")) // 禁用默认回调
                )
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/api/sg/wb/v1/common/oidc/callback")
                )
                .exceptionHandling(ex -> ex.authenticationEntryPoint(myAuthenticationEntryPoint()))
                .oauth2ResourceServer(rs -> rs.jwt(Customizer.withDefaults()));

        return http.build();
    }
}
