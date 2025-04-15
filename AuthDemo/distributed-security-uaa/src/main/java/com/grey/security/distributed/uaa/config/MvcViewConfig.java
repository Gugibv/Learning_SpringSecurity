package com.grey.security.distributed.uaa.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class MvcViewConfig implements WebMvcConfigurer {

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        // 映射 /my/confirm_access 到模板 my/confirm_access.html
        registry.addViewController("/my/confirm_access")
                .setViewName("my/confirm_access");
    }
}