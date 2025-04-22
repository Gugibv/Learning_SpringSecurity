package com.grey.sso.demo.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableConfigurationProperties(SecurityConfig.SecurityProps.class)
public class SecurityConfig {

    private final SecurityProps props;

    public SecurityConfig(SecurityProps props) {
        this.props = props;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(props.getWhitelist().toArray(String[]::new)).permitAll()
                        .anyRequest().authenticated()
                )
                .logout(logout -> logout
                        .logoutSuccessUrl("/") // 登出后跳转首页
                )
                .oauth2Login(withDefaults()); // 使用默认 OAuth2 登录逻辑

        return http.build();
    }

    @ConfigurationProperties(prefix = "app.security")
    public static class SecurityProps {
        private List<String> whitelist = new ArrayList<>();

        public List<String> getWhitelist() {
            return whitelist;
        }

        public void setWhitelist(List<String> whitelist) {
            this.whitelist = whitelist;
        }
    }
}
