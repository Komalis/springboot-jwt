package com.komalis.boilerplate.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.komalis.boilerplate.utils.SecurityConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

import static com.komalis.boilerplate.utils.SecurityConstants.HEADER_STRING;
import static com.komalis.boilerplate.utils.SecurityConstants.TOKEN_PREFIX;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    private SecurityConstants securityConstants;

    public JWTAuthorizationFilter(AuthenticationManager authenticationManager, SecurityConstants securityConstants) {
        super(authenticationManager);
        this.securityConstants = securityConstants;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        // Grab a JWT Token from a request
        String header = request.getHeader(HEADER_STRING);
        if (header == null || !header.startsWith(TOKEN_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }
        else
        {
            // Authenticate the token
            UsernamePasswordAuthenticationToken authentication = getAuthentication(request);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            chain.doFilter(request, response);
        }
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request)
    {
        // Grab a JWT Token from a request
        String token = request.getHeader(HEADER_STRING);
        if (token != null) {
            // Parse the token.
            DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC512(securityConstants.getSecretKey().getBytes()))
                    .build()
                    .verify(token.replace(TOKEN_PREFIX, ""));
            // Get username & a collection of authority
            String username = decodedJWT.getSubject();
            Collection<GrantedAuthority> authorities = Arrays.stream(decodedJWT.getClaims().get("authorities").as(String.class).split(",")).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
            if (username != null) {
                // Create a UsernamePasswordAuth using UserServiceImpl
                return new UsernamePasswordAuthenticationToken(username, null, authorities);
            }
            return null;
        }
        return null;
    }
}
