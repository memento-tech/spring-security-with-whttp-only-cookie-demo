package com.memento.tech.security.http.only.cookie.demo.config;

import com.memento.tech.security.http.only.cookie.demo.config.service.AccessTokenCookieService;
import com.memento.tech.security.http.only.cookie.demo.config.service.JwtTokenService;
import io.micrometer.common.util.StringUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;
import java.util.Optional;

@Component
@RequiredArgsConstructor
@Slf4j
public class HttpOnlyCookieAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenService jwtTokenService;

    private final UserDetailsService userDetailsService;

    private final AccessTokenCookieService accessTokenCookieService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        if (request.getServletPath().startsWith("/secured") && Objects.nonNull(request.getCookies())) {
            Optional<Cookie> accessTokenCookie = accessTokenCookieService.getAccessTokenCookie(request);

            accessTokenCookie.map(Cookie::getValue)
                    .filter(StringUtils::isNotBlank)
                    .ifPresentOrElse(cookieValue -> {
                        var username = jwtTokenService.extractUsername(cookieValue);

                        if (Objects.nonNull(username)) {
                            var authentication = SecurityContextHolder.getContext().getAuthentication();
                            if (Objects.nonNull(authentication)
                                && !authentication.getName().equals(username))
                            {
                                SecurityContextHolder.clearContext();
                            }

                            Optional.ofNullable(userDetailsService.loadUserByUsername(username))
                                    .ifPresentOrElse(userDetails -> {
                                        if (jwtTokenService.validateToken(cookieValue, userDetails)) {
                                            var authToken = new UsernamePasswordAuthenticationToken(
                                                    userDetails,
                                                    null,
                                                    userDetails.getAuthorities()
                                            );
                                            authToken.setDetails(
                                                    new WebAuthenticationDetailsSource().buildDetails(request)
                                            );
                                            SecurityContextHolder.getContext().setAuthentication(authToken);
                                        }
                                    }, () -> {
                                        // user is removed from database or cookie is messed up for some reason, remove cookie data
                                        response.addCookie(accessTokenCookieService.createBlankoHttpOnlyCookie());
                                    });
                        } else {
                            SecurityContextHolder.clearContext();
                        }
                    }, SecurityContextHolder::clearContext);
        }

        filterChain.doFilter(request, response);
    }
}