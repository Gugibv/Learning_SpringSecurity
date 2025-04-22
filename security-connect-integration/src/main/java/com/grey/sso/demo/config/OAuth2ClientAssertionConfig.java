package com.grey.sso.demo.config;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jwt.*;
import org.springframework.context.annotation.*;
import org.springframework.http.*;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.*;
import org.springframework.web.client.RestTemplate;

import java.nio.file.*;
import java.time.*;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * 手写 Provider：仅处理 AUTHORIZATION_CODE，使用 client_assertion
 */
@Configuration
public class OAuth2ClientAssertionConfig {

    @Bean
    OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository registrations,
            OAuth2AuthorizedClientService clientService) {

        /* 1️⃣ 自定义 Provider */
        OAuth2AuthorizedClientProvider provider = context -> {

            // 只接管 authorization_code
            if (!AuthorizationGrantType.AUTHORIZATION_CODE.equals(
                    context.getClientRegistration().getAuthorizationGrantType())) {
                return null;
            }

            /* ---- 取出 code / redirectUri ---- */
            OAuth2AuthorizationExchange exchange =
                    context.getAttribute("authorization_exchange"); // 6.1 没常量，只能裸字串
            if (exchange == null) {          // 第一次重定向阶段，尚无 code
                return null;
            }

            String code        = exchange.getAuthorizationResponse().getCode();
            String redirectUri = exchange.getAuthorizationRequest().getRedirectUri();
            ClientRegistration reg = context.getClientRegistration();

            /* ---- ① 生成 client_assertion(JWT) ---- */
            String assertion = buildClientAssertion(reg);

            /* ---- ② POST 到 token 端点 ---- */
            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
            form.add(OAuth2ParameterNames.CODE, code);
            form.add(OAuth2ParameterNames.REDIRECT_URI, redirectUri);
            form.add(OAuth2ParameterNames.CLIENT_ID, reg.getClientId());
            form.add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
            form.add("client_assertion", assertion);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            Map<String, Object> body = new RestTemplate().postForObject(
                    reg.getProviderDetails().getTokenUri(),
                    new HttpEntity<>(form, headers),
                    Map.class);

            /* ---- ③ 封装返回给 Spring ---- */
            OAuth2AccessToken token = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    (String) body.get(OAuth2ParameterNames.ACCESS_TOKEN),
                    Instant.now(),
                    Instant.now().plusSeconds(Long.parseLong(body.get(OAuth2ParameterNames.EXPIRES_IN).toString()))
            );

            String principal = context.getPrincipal() != null
                    ? context.getPrincipal().getName() : "system";
            return new OAuth2AuthorizedClient(reg, principal, token);
        };

        /* 2️⃣ Manager 交给 Spring */
        AuthorizedClientServiceOAuth2AuthorizedClientManager manager =
                new AuthorizedClientServiceOAuth2AuthorizedClientManager(registrations, clientService);
        manager.setAuthorizedClientProvider(provider);
        return manager;
    }

    /* -------------------------------------------------- */

    /** 用私钥签 JWT → client_assertion */
    private String buildClientAssertion(ClientRegistration reg) {
        try {
            Instant now = Instant.now();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(reg.getClientId())
                    .subject(reg.getClientId())
                    .audience(reg.getProviderDetails().getTokenUri())
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plus(5, ChronoUnit.MINUTES)))
                    .jwtID(UUID.randomUUID().toString())
                    .build();

            /* 读取 EC‑256 私钥 PEM（RSA 也行，换算法即可） */
            String pem = Files.readString(Path.of("keys/private-key.pem"));
            ECKey jwk  = (ECKey) JWK.parseFromPEMEncodedObjects(pem);

            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(jwk.getKeyID()).build(),
                    claims);
            jwt.sign(new ECDSASigner(jwk));
            return jwt.serialize();

        } catch (Exception e) {
            throw new IllegalStateException("create client_assertion failed", e);
        }
    }


    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {

        ClientRegistration lhubsso = ClientRegistration.withRegistrationId("lhubsso")
                .clientId("dw-service-dev")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/lhubsso")
                .scope("openid", "profile")
                .authorizationUri("https://sc.lhubsg.com/sam/idp/a/lhubstg/oidc/auth")
                .tokenUri("https://sc.lhubsg.com/sam/idp/a/lhubstg/oidc/token")
                .jwkSetUri("https://sc.lhubsg.com/sam/idp/a/lhubstg/oidc/.well-known/keys")
                .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT) // 保持一致
                .build();

        return new InMemoryClientRegistrationRepository(lhubsso);
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService(
            ClientRegistrationRepository repo) {
        return new InMemoryOAuth2AuthorizedClientService(repo);
    }

}
