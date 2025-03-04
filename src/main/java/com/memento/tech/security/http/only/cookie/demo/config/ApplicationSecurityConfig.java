package com.memento.tech.security.http.only.cookie.demo.config;

import com.memento.tech.security.http.only.cookie.demo.config.handler.CookieClearLogoutHandler;
import com.memento.tech.security.http.only.cookie.demo.config.handler.HttpOnlyCookieAuthenticationSuccessHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class ApplicationSecurityConfig {

    private static final String[] WHITE_LIST_URL = {
            "/",
            "index.html",
            "/login",
            "/login.html",
            "/public",
            "/ppublic.html",
            "/styles.css"};

    private final HttpOnlyCookieAuthenticationSuccessHandler httpOnlyCookieAuthenticationSuccessHandler;

    private final HttpOnlyCookieAuthenticationFilter httpOnlyCookieAuthenticationFilter;

    private final AuthenticationProvider authenticationProvider;

    private final CookieClearLogoutHandler cookieClearLogoutHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .headers(headersConfigurer -> headersConfigurer.frameOptions(Customizer.withDefaults()).disable())
                .cors(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(request -> request
                        .requestMatchers(WHITE_LIST_URL)
                        .permitAll()
                        .anyRequest()
                        .authenticated())
                .sessionManagement(sessionConfigurer ->
                        sessionConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(httpOnlyCookieAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .logout(customizer -> customizer
                        .addLogoutHandler(cookieClearLogoutHandler)
                        .logoutSuccessUrl("/")
                        .clearAuthentication(true))
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/perform_login")
                        .successHandler(httpOnlyCookieAuthenticationSuccessHandler)
                        .permitAll())
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint((request, response, authException) -> {
                            response.setStatus(HttpStatus.FOUND.value());
                            response.setHeader("Location", "/login");
                        }))
                .build();
    }
}
