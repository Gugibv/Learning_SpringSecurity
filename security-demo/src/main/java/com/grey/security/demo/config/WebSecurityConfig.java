package com.grey.security.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.web.servlet.config.annotation.CorsRegistry;
import  org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
// @EnableWebSecurity //Spring项目总需要添加此注解，SpringBoot项目中不需要
public class WebSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login") // 如果你自己写了页面，可以自定义跳转页面
                        .permitAll()
                        .successHandler(new MyAuthenticationSuccessHandler()) //认证成功时的处理
                        .failureHandler(new MyAuthenticationFailureHandler()) //认证失败时的处理
                )
                .logout(logout -> {
                            logout.logoutSuccessHandler(new MyLogoutSuccessHandler()); //注销成功时的处理
                        })
                .csrf(AbstractHttpConfigurer::disable); // 为了前端测试方便暂时关闭 CSRF
               // .httpBasic(withDefaults()); // 这会让浏览器在访问受保护资源时直接弹出 系统级登录对话框（而不是你写的表单登录页面），适用于非浏览器交互（如 Postman、curl），
                                              // 但不是前后端表单交互的理想方案。



        return http.build();
    }

    /**
     * 配置跨域 CORS 策略（允许前端 React 调用后端 Spring Boot 接口）
     * @return
     */
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOrigins("http://localhost:3000")
                        .allowedMethods("*")
                        .allowCredentials(true);
            }
        };
    }


    @Bean
    public UserDetailsService userDetailsService() {
        DBUserDetailsManager manager = new DBUserDetailsManager();
        return manager;
    }
}