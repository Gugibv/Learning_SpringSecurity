package com.grey.security.demo;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

public class PasswordEncoderUtil {
    public static void main(String[] args) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String rawPassword = "abc";
        String encodedPassword = encoder.encode(rawPassword);
        System.out.println(encodedPassword);
    }


    @Test
    void testPassword() {

        // 工作因子，默认值是10，最小值是4，最大值是31，值越大运算速度越慢
        PasswordEncoder encoder = new BCryptPasswordEncoder(4);
        //明文："password"
        //密文：result，即使明文密码相同，每次生成的密文也不一致
        String result = encoder.encode("password");
        System.out.println(result);

        //密码校验
        Assert.isTrue(encoder.matches("password", result), "密码不一致");
    }
}