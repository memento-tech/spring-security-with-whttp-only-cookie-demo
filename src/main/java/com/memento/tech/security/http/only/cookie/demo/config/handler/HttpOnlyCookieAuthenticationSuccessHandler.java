package com.memento.tech.security.http.only.cookie.demo.config.handler;

import com.memento.tech.security.http.only.cookie.demo.config.service.AccessTokenCookieService;
import com.memento.tech.security.http.only.cookie.demo.config.service.JwtTokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class HttpOnlyCookieAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtTokenService jwtTokenService;

    private final AccessTokenCookieService accessTokenCookieService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        Cookie authCookie = accessTokenCookieService.createHttpOnlyCookie(jwtTokenService.generateToken(authentication.getName()));

        response.addCookie(authCookie);

        response.sendRedirect("/secured");
    }
}
