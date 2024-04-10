package com.grey.springbootsecurity.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;

@RestController
@RequestMapping("/common")
public class LoginController {

    @GetMapping("/getLoginUserByPrincipal")
    public String getLoginUserByPrincipal(Principal principal){

        return principal.getName();

    }
    @GetMapping(value = "/getLoginUserByAuthentication")
    public String currentUserName(Authentication authentication) {

        return authentication.getName();

    }
    @GetMapping(value = "/username")
    public String currentUserNameSimple(HttpServletRequest request) {

        Principal principal = request.getUserPrincipal();
        return principal.getName();

    }

    /**
     * 首先通过SecurityContextHolder获取了当前的安全上下文（SecurityContext），
     * 然后从安全上下文中获取了认证对象（Authentication）。
     * 接着，通过getPrincipal()方法获取了认证对象中的主体对象（Principal）
     * @return
     */
    @PostMapping("/getLoginUser")
    public String getLoginUser(){

        User user = (User)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return user.getUsername();

    }

}
