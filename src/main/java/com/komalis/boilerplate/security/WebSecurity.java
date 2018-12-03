package com.komalis.boilerplate.security;

import com.komalis.boilerplate.user.UserServiceImpl;
import com.komalis.boilerplate.utils.Constants;
import com.komalis.boilerplate.utils.SecurityConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter
{
    @Autowired
    private UserServiceImpl userService;
    @Autowired
    private SecurityConstants securityConstants;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                // Enable CORS
                .cors()
                .and()
                // Disable CSRF
                .csrf()
                .disable()
                // Signup Request
                .authorizeRequests()
                .antMatchers(HttpMethod.POST,"/users/signup")
                .permitAll()
                // Example of a protected page
                .antMatchers("/examples/**")
                .hasAuthority(Constants.ROLE_ADMIN)
                .anyRequest()
                .authenticated()
                .and()
                // JWT Authentication and Authorization
                .addFilter(new JWTAuthenticationFilter(authenticationManager(), securityConstants))
                .addFilter(new JWTAuthorizationFilter(authenticationManager(), securityConstants))
                // Disable session
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // Change the userDetailsService for an authentication, and also the passwordEncoder.
        auth.userDetailsService(userService).passwordEncoder(new BCryptPasswordEncoder());
    }
}
