package com.kot.security1.config;

import com.kot.security1.config.oauth.PrincipalOAuth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration // IoC 빈(bean)을 등록
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록이 됨
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // @Secured를 활성화, @preAutorize 및 @postAutorize 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	private PrincipalOAuth2UserService principalOAuth2UserService;

	@Bean // @Bean: 해당 메서드가 반환하는 오브젝트를 IoC 빈으로 등록
	public BCryptPasswordEncoder encodePwd() {
		return new BCryptPasswordEncoder();
	}

	/*
     구글 로그인이 완료된 뒤의 후처리가 필요함. (Tip. 코드를 받지 말고 액세스토큰+사용자프로필정보를 한번에 받는다.
     1. 코드받기(인증 완료)
     2. 액세스토큰(권한 부여)
     3. 사용자 프로필 정보 가져오기
     4-1. 그 정보를 토대로 회원가입을 자동으로 진행
     4-2. 추가적인 정보(이메일, 전화번호, 이름, 아이디 등)가 필요하면 추가적인 회원가입 과정이 필요
    */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();
		http.authorizeRequests()
			.antMatchers("/user/**").authenticated()
			.antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
			.antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
			.anyRequest().permitAll()
			.and()
			.formLogin()
			.loginPage("/loginForm")
			.loginProcessingUrl("/login") // /login 주소가 호출되면 시큐리티가 낚아채서 대신 로그인을 진행
			.defaultSuccessUrl("/")
			.and() // 구글 로그인 뒤 후처리
			.oauth2Login()
			.loginPage("/loginForm")
			.userInfoEndpoint()
			.userService(principalOAuth2UserService);
	}
}
