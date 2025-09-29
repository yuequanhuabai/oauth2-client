package com.t.b.oauth2client.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Map;

@Service
public class OAuth2Service {
    @Value("${oauth2.client.id}")
    private String clientId;

    @Value("${oauth2.client.secret}")
    private String clientSecret;

    @Value("${oauth2.token.uri}")
    private String tokenUri;

    @Value("${oauth2.userinfo.uri}")
    private String userInfoUri;

    private final WebClient webClient = WebClient.create();

    public Map<String, Object> getAccessToken(String code, String codeVerifier) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("code", code);
        params.add("code_verifier", codeVerifier);
        params.add("client_id", clientId);
        params.add("client_secret", clientSecret);

        Map<String, Object> response = webClient.post()
                .uri(tokenUri)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue(params)
                .retrieve()
                .bodyToMono(Map.class)
                .block();

        if (response == null) {
            throw new RuntimeException("授权服务器未返回响应");
        }

        if (response.containsKey("error")) {
            return response;
        }

        return response;
    }

    public Map<String, Object> getUserInfo(String accessToken) {
        return webClient.get()
                .uri(userInfoUri)
                .header("Authorization", "Bearer " + accessToken)
                .retrieve()
                .bodyToMono(Map.class)
                .block();
    }

}
