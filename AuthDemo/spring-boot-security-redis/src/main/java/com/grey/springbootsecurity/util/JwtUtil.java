package com.grey.springbootsecurity.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

public class JwtUtil {

    //有效期为 一个小时
    public static final Long JWT_TTL = 60*60*1000L;

    public static final String JWT_KEY = "TestKey";

    public static String getUUID(){
        String token = UUID.randomUUID().toString().replace("-","");
        return token;
    }

    public static String createJWT(String subject){
        JwtBuilder builder = getJwtBuilder(subject,null,getUUID());
        return  builder.compact();
    }

    public static String createJWT(String subject,Long ttlMillis){
        JwtBuilder builder = getJwtBuilder(subject,ttlMillis,getUUID());//设置过期时间
        return  builder.compact();
    }

    private static JwtBuilder getJwtBuilder(String subject, Long ttlMillis,String uuid){
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
        SecretKey secretKey = generalKey();
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        if(ttlMillis == null){
            ttlMillis = JwtUtil.JWT_TTL;
        }
        long expMillis = nowMillis + ttlMillis;
        Date expDate = new Date(expMillis);
        return Jwts.builder()
                .setId(uuid) //唯一id
                .setSubject(subject) // 主题，可以时json数据
                .setIssuer("Grey")//签发者
                .setIssuedAt(now) //签发时间
                .signWith(signatureAlgorithm,secretKey)//使用HS256对称加密算法，第二个参数为密钥
                .setExpiration(expDate);
    }

    public static String createJWT(String id ,String subject ,Long ttlMillis){
        JwtBuilder builder = getJwtBuilder(subject,ttlMillis,id);
        return builder.compact();
    }


    public static SecretKey generalKey(){
        byte[] encodedKey = Base64.getDecoder().decode(JwtUtil.JWT_KEY);
        SecretKey key = new SecretKeySpec(encodedKey,0 ,encodedKey.length,"AES");
        return key;

    }


    public static Claims parseJWT(String jwt) throws Exception{
        SecretKey secretKey = generalKey();
        return Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(jwt)
                .getBody();
    }


    public static void main(String []args) throws Exception {
        String jwt = createJWT("1001");
        System.out.println(jwt);

        Claims claims = parseJWT(jwt);
        System.out.println(claims.getSubject());
    }

}
