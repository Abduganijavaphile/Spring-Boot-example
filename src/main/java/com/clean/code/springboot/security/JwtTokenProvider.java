package com.clean.code.springboot.security;

import com.auth0.jwt.JWT;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.clean.code.springboot.domain.Role;
import org.jose4j.jwt.JwtClaims;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.util.*;

@Component
public class JwtTokenProvider {
    @Value("${jwt.token.secret}")
    private String secret;
    @Value("${jwt.token.validity}")
    private long validity;
    private Long expireMilliSecund = 360000L;
    private String key = "springboot";
    private final UserDetailsService userDetailsService;


    public JwtTokenProvider(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }


    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        return bCryptPasswordEncoder;
    }
    @PostConstruct
    protected void init(){
        secret = Base64.getEncoder().encodeToString(secret.getBytes());
    }
    public String createToken(String username, Set<Role> roles){
        return JWT.create()
                .withSubject(username)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(new Date().getTime()+expireMilliSecund))
                .sign(Algorithm.HMAC512(key));
    }


    public boolean validateToken(String token){
        DecodedJWT decode = JWT.decode(token);
        if (decode.getExpiresAt().before(Calendar.getInstance().getTime())) {
            throw new RuntimeException("Exired token!");
        }
        return true;
    }
    public String resolveToken(HttpServletRequest request){
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7);
        }
        return null;
    }
    public Authentication getAuthentication(String token) {
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(getUser(token));
        return new UsernamePasswordAuthenticationToken(userDetails.getUsername(),"",
                userDetails.getAuthorities());
    }
    private String getUser(String token) {
        DecodedJWT verify = JWT.require(Algorithm.HMAC512(key)).build().verify(token);
        return verify.getSubject();
    }
}
