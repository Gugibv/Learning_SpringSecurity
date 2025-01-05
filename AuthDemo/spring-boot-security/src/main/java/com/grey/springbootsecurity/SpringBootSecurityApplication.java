package com.grey.springbootsecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;

@SpringBootApplication
@EnableWebSecurity
public class SpringBootSecurityApplication {
    public static void main(String[] args)
    {

       ConfigurableApplicationContext context=  SpringApplication.run(SpringBootSecurityApplication.class, args);

       // security 中的所有过滤器
        DefaultSecurityFilterChain bean = context.getBean(DefaultSecurityFilterChain.class);

        System.out.println(bean);
    }
}
