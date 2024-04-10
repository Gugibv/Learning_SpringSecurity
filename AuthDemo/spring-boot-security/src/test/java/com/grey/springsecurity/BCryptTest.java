package com.grey.springsecurity;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class BCryptTest {
      public static void main(String[]args){
          BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
          String password = "admin";

          for(int i =0;i<3;i++){

              // BCrypt.hashpw(rawPassword.toString(), salt)  添加不同的盐，来实现每次的密文不同
              String encodedString = encoder.encode(password) ;
              System.out.println(encoder.matches(password,encodedString) +"  每次加密后的字符串不一样："+ encodedString);
          }
      }

}
