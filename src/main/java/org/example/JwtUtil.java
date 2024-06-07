package org.example;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Date;

public class JwtUtil {
    private static final String SECRET_KEY =
            "mySecretKeyForJwtSigningMySecretKeyForJwtSigning"; //
    // 必ず十分な長さのキーを使用
    private static final Key    key        = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());

    public static String generateToken(String subject, String role) {
        return Jwts.builder()
                   .setSubject(subject)
                   .claim("role", role)
                   .setExpiration(new Date(System.currentTimeMillis() + 24 * 60 * 60 * 1000)) // 1時間有効
                   .signWith(key, SignatureAlgorithm.HS256)
                   .compact();
    }

    public static void decodeToken(String token) {
        Jws<Claims> jws = Jwts.parserBuilder()
                              .setSigningKey(key)
                              .build()
                              .parseClaimsJws(token);

        System.out.println("Subject: " + jws.getBody().getSubject());
        System.out.println("Role: " + jws.getBody().get("role"));
        System.out.println("Expiration: " + jws.getBody().getExpiration());
    }

    public static void main(String[] args) {
        String adminToken = generateToken("admin", "ADMIN");
        System.out.println("Admin Token: " + adminToken);
        decodeToken(adminToken);

        String userToken = generateToken("user", "USER");
        System.out.println("User Token: " + userToken);
        decodeToken(userToken);
    }
}