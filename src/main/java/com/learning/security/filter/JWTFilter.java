package com.learning.security.filter;

import com.learning.security.service.JWTService;
import com.learning.security.service.MyUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.ApplicationContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//Creating a custom filter for JWT token authentication by extending a OncePerRequestFilter
@Component
public class JWTFilter extends OncePerRequestFilter {

    @Autowired
    private JWTService jwtService;

    @Autowired
    private ApplicationContext context;

//    This is an abstact method inside OncePerRequestFilter which we use to authenticate the token
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//       Fetching authorization header from the request
        String authHeader = request.getHeader("Authorization");
        String token = null;
        String userName = null;

//       Client will send token in the format Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJsYWxpdGhhIiwiaWF0IjoxNzI3NDM5NDA5LCJleHAiOjE3Mjc0Mzk1MTd9.Qwg4xkMe1h5Gh21BPzBl1Z9BZ_TpfTsLQ4yv_BX56Gc
//       So we need to remove the Bearer part and then authenticate the token
        if(authHeader != null && authHeader.startsWith("Bearer ")){
            token = authHeader.substring(7);
            userName = jwtService.extractUsername(token);
        }

//        Check if userName is not null and that the user is not already authenticated
        if(userName != null && SecurityContextHolder.getContext().getAuthentication() == null){
//        If the above the checks are ok, we only need to validate the token and then forward the request to the UserNamePasswordAuthenticationFilter
//        Fetching the userDetails from DB by fetching the UserDetails bean using ApplicationContext
            UserDetails userDetails = context.getBean(MyUserDetailsService.class).loadUserByUsername(userName);
            if(jwtService.validateToken(token,userDetails)){
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
//               The token should know about the request details
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//                Adding token to the chain
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
//      Forwarding details to the next filter
        filterChain.doFilter(request,response);

    }
}
