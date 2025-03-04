package com.memento.tech.security.http.only.cookie.demo.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebMvcConfiguration implements WebMvcConfigurer {

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/").setViewName("forward:/index.html");
        registry.addViewController("/login").setViewName("forward:/login.html");

        registry.addViewController("/public**").setViewName("forward:/ppublic.html");
        registry.addViewController("/public/**").setViewName("forward:/ppublic.html");

        registry.addViewController("/secured**").setViewName("forward:/secure.html");
        registry.addViewController("/secured/**").setViewName("forward:/secure.html");
    }

}
