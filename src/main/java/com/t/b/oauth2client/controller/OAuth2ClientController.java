package com.t.b.oauth2client.controller;


import com.t.b.oauth2client.service.OAuth2Service;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Controller
public class OAuth2ClientController {

    @Value("${oauth2.client.id}")
    private String clientId;

    @Value("${oauth2.authorization.uri}")
    private String authorizationUri;

    @Value("${oauth2.redirect.uri}")
    private String redirectUri;

    @Autowired
    private OAuth2Service oauth2Service;

    // 首页
    @GetMapping("/")
    public String home() {
        return "home";
    }

    // 1. 发起OAuth2授权请求
    @GetMapping("/login")
    public String login(HttpSession session) {
        // 生成state防止CSRF攻击
        String state = UUID.randomUUID().toString();
        session.setAttribute("oauth2_state", state);

        // 构建授权URL
        String authUrl = authorizationUri +
                "?client_id=" + clientId +
                "&redirect_uri=" + redirectUri +
                "&response_type=code" +
                "&state=" + state;

        return "redirect:" + authUrl;
    }

    // 2. 处理授权回调页面展示，由前端脚本执行交换
    @GetMapping("/callback")
    public String callback() {
        return "callback";
    }

    @PostMapping(value = "/token", consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public Map<String, Object> exchangeToken(@RequestBody Map<String, String> payload, HttpSession session) {
        String code = payload.get("code");
        String codeVerifier = payload.get("code_verifier");
        if (code == null || code.isBlank() || codeVerifier == null || codeVerifier.isBlank()) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", "invalid_request");
            return error;
        }

        Map<String, Object> tokenResponse = oauth2Service.getAccessToken(code, codeVerifier);
        Object accessToken = tokenResponse.get("access_token");
        if (accessToken instanceof String tokenValue && !tokenValue.isBlank()) {
            session.setAttribute("access_token", tokenValue);
        }
        return tokenResponse;
    }

    @GetMapping("/userinfo")
    @ResponseBody
    public Map<String, Object> userinfo(@RequestHeader(value = "Authorization", required = false) String authorization,
                                        HttpSession session) {
        String token = null;
        if (authorization != null && authorization.startsWith("Bearer ")) {
            token = authorization.substring(7);
        } else {
            Object stored = session.getAttribute("access_token");
            if (stored instanceof String storedToken) {
                token = storedToken;
            }
        }

        if (token == null || token.isBlank()) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", "invalid_token");
            return error;
        }

        return oauth2Service.getUserInfo(token);
    }

    // 3. 显示用户信息
    @GetMapping("/user")
    public String user(HttpSession session, Model model) {
        Map<String, Object> userInfo = (Map<String, Object>) session.getAttribute("user_info");
        if (userInfo == null) {
            return "redirect:/";
        }

        model.addAttribute("userInfo", userInfo);
        return "user";
    }
}
