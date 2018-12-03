package com.komalis.boilerplate.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.komalis.boilerplate.user.User;
import com.komalis.boilerplate.utils.Constants;
import com.komalis.boilerplate.utils.SecurityConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import static com.komalis.boilerplate.utils.SecurityConstants.*;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter
{
    private AuthenticationManager authenticationManager;
    private SecurityConstants securityConstants;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager, SecurityConstants securityConstants) {
        this.authenticationManager = authenticationManager;
        this.securityConstants = securityConstants;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        User user = null;
        try {
            // Get user from JSON in the Request
            user = new ObjectMapper().readValue(request.getInputStream(), User.class);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        // Get user from authResult
        User user = (User) authResult.getPrincipal();
        // Generate a string for authorities
        String authorities = user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));
        // Set an expiration date
        Date expiresAt = Calendar.getInstance().getTime();
        expiresAt.setTime(expiresAt.getTime() + EXPIRATION_TIME);
        // Create a JWT Token
        String token = JWT.create()
                .withSubject(user.getUsername())
                .withClaim("authorities", authorities)
                .withExpiresAt(expiresAt)
                .sign(Algorithm.HMAC512(securityConstants.getSecretKey().getBytes()));
        // Add the JWT Token to the headers answer
        response.addHeader(HEADER_STRING, TOKEN_PREFIX + token);
    }
}
