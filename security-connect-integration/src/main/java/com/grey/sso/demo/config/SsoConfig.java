package com.grey.sso.demo.config;

import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.*;

import java.nio.file.Files;
import java.nio.file.Path;
@Configuration
public class SsoConfig {

    /**
     * ① 让 Spring 能用私钥签 client_assertion（private_key_jwt）
     */
    @Bean
    public JwtEncoder jwtEncoder() throws Exception {

        String pem = Files.readString(Path.of("keys/private-key.pem"));
        JWK jwk    = JWK.parseFromPEMEncodedObjects(pem);

        JWKSource<SecurityContext> jwkSource =
                (selector, ctx) -> selector.select(new JWKSet(jwk));

        return new NimbusJwtEncoder(jwkSource);
    }


    /**
     * ② 如果你在后台代码里需要主动拿 token，可注入这个 manager。
     *    对于普通浏览器登录流程，其实不写也没问题。
     */
    @Bean
    OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository registrations,
            OAuth2AuthorizedClientService clientService) {      // ⬅️ 保持原来的 svc

        return new AuthorizedClientServiceOAuth2AuthorizedClientManager(
                registrations, clientService);
    }

}
