package io.security.basicsecurity;

import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;


@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;

    @Override

    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests() /* 자원경로의 범위는 디테일 한게 먼저 */
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();

        http.formLogin();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user")
                .password("{noop}1111") /* {noop} 암호화를 평문으로 */
                .roles("USER");

        auth.inMemoryAuthentication().withUser("sys")
                .password("{noop}1111")
                .roles("SYS", "USER");

        auth.inMemoryAuthentication()
                .withUser("admin")
                .password("{noop}1111")
                .roles("ADMIN", "SYS", "USER");
    }
}
