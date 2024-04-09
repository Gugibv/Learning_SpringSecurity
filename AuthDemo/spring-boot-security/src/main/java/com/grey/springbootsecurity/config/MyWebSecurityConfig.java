package com.grey.springbootsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

/**
 * 注入一个自定义的配置
 */
@EnableWebSecurity
public class MyWebSecurityConfig {

    //配置安全拦截策略
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.csrf(AbstractHttpConfigurer::disable)   //关闭csrf跨域检查
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/mobile/**").hasAuthority("mobile") //配置资源权限
                        .requestMatchers("/salary/**").hasAuthority("salary")
                        .requestMatchers("/common/**").permitAll() //common下的请求直接通过
                        .anyRequest().authenticated())  //其他请求需要登录
                .formLogin(form -> form
                        .defaultSuccessUrl("/main.html")
                        .failureUrl("/common/loginFailed"));//可从默认的login页面登录，并且登录后跳转到main.html
        return http.build();
    }


}