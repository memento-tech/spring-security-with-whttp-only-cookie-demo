package com.memento.tech.security.http.only.cookie.demo.config.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Objects;

import static com.memento.tech.security.http.only.cookie.demo.config.constants.Constants.COOKIE_NAME;

@Service
public class CookieClearLogoutHandler implements LogoutHandler {

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (Objects.nonNull(request.getCookies())) {
            Arrays.stream(request.getCookies())
                    .filter(cookie -> cookie.getName().equals(COOKIE_NAME))
                    .peek(cookie -> cookie.setValue(""))
                    .forEach(response::addCookie);
        }
    }
}
