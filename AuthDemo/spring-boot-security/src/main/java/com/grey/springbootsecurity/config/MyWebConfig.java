package com.grey.springbootsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class MyWebConfig implements WebMvcConfigurer {


    /**
     * 在Spring MVC中注册一个ViewController，将默认的根路径("/")重定向到"/login"路径上。
     * 这意味着当用户访问根路径时，会被重定向到登录页面，提供了一种简单的方式来设置默认页面跳转。
     * 这里的"/login"路径通常由Spring Security提供，用于处理登录相关的请求。
     * @param registry ViewControllerRegistry对象，用于注册ViewController
     */
    @Override
    public void addViewControllers(ViewControllerRegistry registry)
    {
        registry.addViewController("/").setViewName("redirect:/login");
    }


    /**
     * 自行注入一个PasswordEncoder。
     * 返回 NoOpPasswordEncoder.getInstance() 则意味着不对输入密码进行加密
     */
    @Bean
    public PasswordEncoder getPassWordEncoder(){
        return new BCryptPasswordEncoder(10);

    }

    /**
     * 注入一个自定义的 UserDetailsService 实例。
     * 如果应用中没有自定义的 UserDetailsService 实现类，Spring Security 会在 UserDetailsServiceAutoConfiguration 中默认注入一个包含用户信息的 InMemoryUserDetailsManager。
     * 另外，也可以通过重写 configure(AuthenticationManagerBuilder auth) 方法并注入 authenticationManagerBean 的方式来自定义认证管理器。
     * 在这个示例中，返回的是一个 InMemoryUserDetailsManager 实例，用于在内存中存储用户信息，方便快速搭建简单的认证系统。
     * 对于更复杂的场景，可以使用 JdbcUserDetailsManager 从数据库中获取用户信息。
     */
    @Bean
    public UserDetailsService userDetailsService(){
        return new InMemoryUserDetailsManager(
                User.withUsername("admin").password(getPassWordEncoder().encode("admin")).authorities("mobile","salary").build(),
                User.withUsername("manager").password(getPassWordEncoder().encode("manager")).authorities("salary").build(),
                User.withUsername("worker").password(getPassWordEncoder().encode("worker")).authorities("worker").build()
        );
    }
}
