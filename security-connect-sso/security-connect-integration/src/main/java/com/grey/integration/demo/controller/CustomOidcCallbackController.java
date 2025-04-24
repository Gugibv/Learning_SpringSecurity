package com.grey.integration.demo.controller;


import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jwt.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/api/sg/wb/v1/common/oidc")
public class CustomOidcCallbackController {

    @Value("${spring.security.oauth2.client.registration.lhubsso.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.provider.lhubsso.token-uri}")
    private String tokenUri;

    @Value("${spring.security.oauth2.client.registration.lhubsso.redirect-uri}")
    private String redirectUri;

    @PostMapping("/callback")
    public void handleCallback(@RequestParam("code") String code,
                               @RequestParam("state") String state,
                               HttpServletRequest request,
                               HttpServletResponse response) throws Exception {
        System.out.println("--------------------------------callback--------------------------------------");

        // 1. 构建 Token 请求参数
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.GRANT_TYPE, "authorization_code");
        params.add(OAuth2ParameterNames.CODE, code);
        params.add(OAuth2ParameterNames.REDIRECT_URI, redirectUri);
        params.add(OAuth2ParameterNames.CLIENT_ID, clientId);
        params.add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        params.add("client_assertion", generateClientAssertion());

        // 2. 发起 Token 请求
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(params, headers);

        ResponseEntity<Map> tokenResponse = restTemplate.exchange(
                tokenUri, HttpMethod.POST, entity, Map.class);

        if (!tokenResponse.getStatusCode().is2xxSuccessful()) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token exchange failed");
            return;
        }

        // 3. 提取 ID Token 并解析
        Map<String, Object> body = tokenResponse.getBody();
        String idToken = (String) body.get("id_token");
        SignedJWT jwt = (SignedJWT) JWTParser.parse(idToken);
        String username = jwt.getJWTClaimsSet().getSubject(); // 可改成 name/email

        // 4. 创建 Spring Security 登录会话
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(username, null, List.of());

        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 5. 跳转到首页或原始页面
        response.sendRedirect("/");
    }

    /**
     * 生成 client_assertion（JWT 签名）
     */
    private String generateClientAssertion() throws Exception {

        /* 1、读取并解析私钥（支持 PEM / JWK 字符串） */
        String pemOrJson = Files.readString(Path.of("src/main/resources/keys/private-key.pem"));
        JWK jwk = JWK.parseFromPEMEncodedObjects(pemOrJson);   // 同时支持 PEM & JWK

        /* 2、构造声明集 (JWT Claims) */
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(clientId)
                .subject(clientId)
                .audience(tokenUri)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300)))   // 5 分钟过期
                .jwtID(UUID.randomUUID().toString())
                .build();

        /* 3、选择算法 & 创建 signer */
        JWSHeader header;
        JWSSigner signer;
        if (jwk instanceof ECKey ecKey) {
            header  = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .keyID(ecKey.getKeyID())
                    .type(JOSEObjectType.JWT)
                    .build();
            signer  = new ECDSASigner(ecKey);
        } else if (jwk instanceof RSAKey rsaKey) {
            header  = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(rsaKey.getKeyID())
                    .type(JOSEObjectType.JWT)
                    .build();
            signer  = new RSASSASigner(rsaKey);
        } else {
            throw new IllegalStateException("Unsupported key type: " + jwk.getKeyType());
        }

        /* 4、 签名并序列化 */
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(signer);
        return jwt.serialize();            // ← 这就是 client_assertion
    }
}
