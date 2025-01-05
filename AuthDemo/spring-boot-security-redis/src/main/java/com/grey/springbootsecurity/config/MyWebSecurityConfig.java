package com.grey.springbootsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

/**
 * 注入一个自定义的配置
 */
@Configuration
@EnableWebSecurity // 启用 Spring Security，表示该类是 Spring Security 配置的一部分。
// 它会启用 Web 安全的默认设置，同时你可以自定义设置
public class MyWebSecurityConfig {

    //配置安全拦截策略
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.csrf(AbstractHttpConfigurer::disable)     //关闭csrf跨域检查
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/mobile/**").hasAuthority("mobile") //配置资源权限
                        .requestMatchers("/salary/**").hasAuthority("salary")
                        .requestMatchers("/common/**","/index.html","/css/**","/img/**","/js/**")
                        .permitAll()      //common下的请求直接通过
                        .anyRequest().authenticated())   //其他请求需要登录
                .formLogin(form -> form                  //formLogin : 配置基于表单的登录认证
                        .loginPage("/index.html")        //设置自定义的登录页面路径，
                        //用户访问需要登录的页面时，会跳转到 index.html 页面
                        .loginProcessingUrl("/login")    //当用户在登录页面提交表单时，
                        //表单会通过 POST 请求提交到 /login URL
                        .defaultSuccessUrl("/main.html") //设置用户登录成功后默认跳转到的页面
                        .failureUrl("/common/loginFailed")); //置登录失败后跳转的页面

        return http.build();
    }
}