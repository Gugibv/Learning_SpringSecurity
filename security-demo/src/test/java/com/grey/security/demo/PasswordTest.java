package com.grey.security.demo;

//import org.springframework.security.crypto.Bcr

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import org.springframework.security.crypto.bcrypt.BCrypt;

public class PasswordTest {

    public static boolean checkpw(String plaintext, String hashed) {
        byte[] passwordb = plaintext.getBytes(StandardCharsets.UTF_8);
        return equalsNoEarlyReturn(hashed, hashpwforcheck(passwordb, hashed));
    }

    static boolean equalsNoEarlyReturn(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
    private static String hashpwforcheck(byte[] passwordb, String salt) {
        return BCrypt.hashpw(passwordb, salt);
    }


    public static void main(String []args){
        String rawPassword = "abc";
        String encodedPassword = "$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW";
        Boolean flag =  BCrypt.checkpw(rawPassword.toString(), encodedPassword);
        System.out.println(flag);
    }
}
