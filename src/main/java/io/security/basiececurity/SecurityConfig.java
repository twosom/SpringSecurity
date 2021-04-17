package io.security.basiececurity;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.http.HttpSession;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .anyRequest().authenticated();

        http.formLogin()
                .successHandler((request, response, authentication) -> {
                    /* HttpSessionRequestCache 안에 AuthenticationEntryPoint 가 발생하기 전 원래 가고자 하였던 요청정보가 저장되어있다. */
                    RequestCache requestCache = new HttpSessionRequestCache();
                    log.info(String.valueOf(requestCache));
                    /* SavedRequest 안에 저장되어 있다. */
                    SavedRequest savedRequest = requestCache.getRequest(request, response);
                    log.info(String.valueOf(savedRequest));

                    /* 원래 가고자하였던 EntryPoint */
                    String redirectUrl = savedRequest.getRedirectUrl();
                    response.sendRedirect(redirectUrl);
                });


        http.exceptionHandling()
//                .authenticationEntryPoint((request, response, authException) -> {
//                    log.warn(authException.getMessage());
//                    /* Spring 에서 제공하는 Login 페이지가 아닌 사용자가 직접 만든 login 페이지로 이동. */
//                    response.sendRedirect("/login");
//                })
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    log.warn(accessDeniedException.getMessage());
                    response.sendRedirect("/denied");
                });
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        auth.inMemoryAuthentication()
                .withUser("user")
                .password("{noop}1111")
                .roles("USER");

        auth.inMemoryAuthentication()
                .withUser("sys")
                .password("{noop}1111")
                .roles("SYS");

        auth.inMemoryAuthentication()
                .withUser("admin")
                .password("{noop}1111")
                .roles("ADMIN", "SYS", "USER");
    }
}
