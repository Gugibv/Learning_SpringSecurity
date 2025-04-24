package com.grey.integration.demo.controller;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jwt.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.util.*;

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
    public void handleCallback(@RequestParam(value = "code", required = false) String code,
                               @RequestParam(value = "state", required = false) String state,
                               HttpServletRequest request,
                               HttpServletResponse response) throws Exception {
        System.out.println("--------------------------------callback--------------------------------------");

        if (code == null || state == null) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing authorization code or state");
            return;
        }

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add(OAuth2ParameterNames.GRANT_TYPE, "authorization_code");
        params.add(OAuth2ParameterNames.CODE, code);
        params.add(OAuth2ParameterNames.REDIRECT_URI, redirectUri);
        params.add(OAuth2ParameterNames.CLIENT_ID, clientId);
        params.add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        params.add("client_assertion", generateClientAssertion());

        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(params, headers);

        ResponseEntity<Map> tokenResponse = restTemplate.exchange(tokenUri, HttpMethod.POST, entity, Map.class);

        if (!tokenResponse.getStatusCode().is2xxSuccessful()) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token exchange failed");
            return;
        }

        Map<String, Object> body = tokenResponse.getBody();
        String idToken = (String) body.get("id_token");

        JWT parsedJwt = JWTParser.parse(idToken);

        if (parsedJwt instanceof EncryptedJWT encryptedJWT) {
            JWEDecrypter decrypter = new ECDHDecrypter(loadPrivateECKey());
            encryptedJWT.decrypt(decrypter);
            parsedJwt = encryptedJWT.getPayload().toSignedJWT();
        }

        if (!(parsedJwt instanceof SignedJWT signedJWT)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid ID token");
            return;
        }

        String username = signedJWT.getJWTClaimsSet().getSubject();
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(username, null, List.of());
        SecurityContextHolder.getContext().setAuthentication(authentication);

        response.sendRedirect("/");
    }

    private ECPrivateKey loadPrivateECKey() throws Exception {
        String json = new String(new ClassPathResource("keys/private-key.pem").getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        ECKey ecKey = ECKey.parse(json);
        return ecKey.toECPrivateKey();
    }

    private String generateClientAssertion() throws Exception {
        String json = new String(new ClassPathResource("keys/private-key.pem").getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        JWK jwk = JWK.parse(json);

        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(clientId)
                .subject(clientId)
                .audience(tokenUri)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300)))
                .jwtID(UUID.randomUUID().toString())
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(jwk.getKeyID())
                .type(JOSEObjectType.JWT)
                .build();

        JWSSigner signer = new ECDSASigner(((ECKey) jwk));
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(signer);
        return jwt.serialize();
    }
}
