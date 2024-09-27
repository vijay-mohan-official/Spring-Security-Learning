package com.learning.security.config;

import com.learning.security.filter.JwtFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtFilter jwtFilter;

//    Creating a custom filter chain based on our requirements
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

//      Disabling CSRF
//        httpSecurity.csrf(customizer -> customizer.disable());
//      Authorizing all Http requests
//        httpSecurity.authorizeHttpRequests(request -> request.anyRequest().authenticated());
//      Enabling access using default credentials in browser(Disable to use resource as stateless in browser)
//        httpSecurity.formLogin(Customizer.withDefaults());
//      For enabling access for RestClients(Postman)
//        httpSecurity.httpBasic(Customizer.withDefaults());
//      Make Http stateless(No need to worry about sessionId)
//        httpSecurity.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

//        return httpSecurity.build();

//      Using Builder pattern above code is being replaced
        return httpSecurity
//                .csrf(customizer -> customizer.disable())
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(request-> request
//                        .requestMatchers("/h2-console/**").permitAll()  //Added for skipping auth for H2 DB
                        .requestMatchers("register","login").permitAll()   //Added for skipping security for register and login (Common practice)
                        .anyRequest().authenticated())  // Default authentication is UsernamePasswordAuthenticationFilter
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(session->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                Adding a new JWT Token filter before UsernamePasswordAuthenticationFilter filter
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .build();

    }

//    Creating a custom user details bean to override credentials configured in properties file and use credentials configured in code
//    @Bean
//    public UserDetailsService userDetailsService(){
//
//        UserDetails user1 = User
//                .withDefaultPasswordEncoder()
//                .username("mohan")
//                .password("kumar")
//                .roles("USER")
//                .build();
//
//        UserDetails user2 = User
//                .withDefaultPasswordEncoder()
//                .username("smitha")
//                .password("mohan")
//                .roles("ADMIN")
//                .build();
//
//        return new InMemoryUserDetailsManager(user1,user2);
//    }

//  Authentication Manager for JWT added to get control of Authentication manager and speak with Authentication Provider
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

//    From webpage - Credentials(UserName, Password) is passed as Authentication Object > Authentication Provider > Authenticated object
    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(new BCryptPasswordEncoder(12));
        provider.setUserDetailsService(userDetailsService);
        return provider;
    }


}
