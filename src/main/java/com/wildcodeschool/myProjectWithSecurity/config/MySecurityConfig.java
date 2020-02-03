package com.wildcodeschool.myProjectWithSecurity.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class MySecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
	    http
        .authorizeRequests()
	        .antMatchers("/").permitAll()
	        .antMatchers("/avengers/assemble").hasRole("HERO")
	        .antMatchers("/secret-bases").hasRole("DIRECTOR")
	        .anyRequest().authenticated()
        .and()
        	.formLogin()
        .and()
        	.httpBasic();
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		
		PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

		auth.inMemoryAuthentication()
			.withUser("Nick Fury")
	        .password(encoder.encode("1234"))
	        .roles("DIRECTOR")
        .and()
        	.withUser("Tony Stark")
	        .password(encoder.encode("abcd"))
	        .roles("HERO")
        .and()
	    	.withUser("Steve Guy")
	        .password(encoder.encode("0000"))
	        .roles("");
	}
}