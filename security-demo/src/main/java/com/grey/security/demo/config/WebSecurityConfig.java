package com.grey.security.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
// @EnableWebSecurity //Spring项目总需要添加此注解，SpringBoot项目中不需要
public class WebSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .formLogin(withDefaults())   // 表单登录（默认登录页 /login）
                .httpBasic(withDefaults()); // 支持 HTTP Basic 认证

        return http.build();
    }
/*
    @Bean
    public UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withDefaultPasswordEncoder().username("grey").password("password").roles("USER").build());
        return manager;
    }
*/

    @Bean
    public UserDetailsService userDetailsService() {
        DBUserDetailsManager manager = new DBUserDetailsManager();
        return manager;
    }
}