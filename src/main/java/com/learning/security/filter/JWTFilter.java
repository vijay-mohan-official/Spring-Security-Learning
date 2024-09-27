package com.learning.security.filter;

import com.learning.security.service.JWTService;
import com.learning.security.service.MyUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.catalina.core.ApplicationContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JWTFilter extends OncePerRequestFilter {

    @Autowired
    private JWTService jwtService;

    @Autowired
    private ApplicationContext applicationContext;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//       Client will send token in the format Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJsYWxpdGhhIiwiaWF0IjoxNzI3NDM5NDA5LCJleHAiOjE3Mjc0Mzk1MTd9.Qwg4xkMe1h5Gh21BPzBl1Z9BZ_TpfTsLQ4yv_BX56Gc
//       So we need to remove the Bearer part and then authenticate the token
        String authHeader = request.getHeader("Authorization");
        String token = null;
        String userName = null;

        if(authHeader != null && authHeader.startsWith("Bearer ")){
            token = authHeader.substring(7);
            userName = jwtService.extractUsername();
        }

//        Check if userName is not null and that the user is not already authenticated
        if(userName != null && SecurityContextHolder.getContext().getAuthentication() == null){
//        If the above the checks are ok, we only need to validate the token and then forward the request to the UserNamePasswordAuthenticationFilter
            UserDetails userDetails = applicationContext.getBean(MyUserDetailsService.class);
            if(jwtService.validateToken(token,userDetails)){

            }
        }
    }
}
