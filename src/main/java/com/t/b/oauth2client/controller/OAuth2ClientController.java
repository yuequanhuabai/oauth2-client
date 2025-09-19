package com.t.b.oauth2client.controller;


import com.t.b.oauth2client.service.OAuth2Service;
import jakarta.servlet.http.HttpSession;
import lombok.Value;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

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

    // 2. 处理授权回调
    @GetMapping("/callback")
    public String callback(@RequestParam String code,
                           @RequestParam String state,
                           HttpSession session,
                           Model model) {

        // 验证state
        String sessionState = (String) session.getAttribute("oauth2_state");
        if (!state.equals(sessionState)) {
            model.addAttribute("error", "状态验证失败");
            return "error";
        }

        try {
            // 用授权码换取访问令牌
            String accessToken = oauth2Service.getAccessToken(code);
            session.setAttribute("access_token", accessToken);

            // 获取用户信息
            Map<String, Object> userInfo = oauth2Service.getUserInfo(accessToken);
            session.setAttribute("user_info", userInfo);

            return "redirect:/user";
        } catch (Exception e) {
            model.addAttribute("error", "获取令牌失败: " + e.getMessage());
            return "error";
        }
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
