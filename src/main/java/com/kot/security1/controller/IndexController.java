package com.kot.security1.controller;

import com.kot.security1.config.auth.PrincipalDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.kot.security1.model.User;
import com.kot.security1.repository.UserRepository;

@Controller // View를 리턴함
public class IndexController {
	@Autowired
	private UserRepository userRepository;
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	@GetMapping("/test/login")
	public @ResponseBody String testLogin(
			Authentication authentication,
			@AuthenticationPrincipal PrincipalDetails userDetails){ // @AuthenticationPrincipal: 세션 정보에 접근
		System.out.println("/test/login ======================================");
		
		// 1. Authentication 객체로 정보 받기
		PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
		System.out.println("authentication: " +principalDetails.getUser());
		// 2. @AuthenticationPrincipal PrincipalDetails implements UserDetails 객체로 정보 받기
		System.out.println("userDetails: " + userDetails.getUser());
		return "세션 정보 확인 수행";
	}

	@GetMapping("/test/oauth/login")
	public @ResponseBody String testOAuthLogin(
			Authentication authentication,
			@AuthenticationPrincipal OAuth2User oAuth2User2){ // @AuthenticationPrincipal: 세션 정보에 접근
		System.out.println("/test/oauth/login ======================================");

		// 1.
		OAuth2User oAuth2User = (OAuth2User)authentication.getPrincipal();
		System.out.println("authentication: " +oAuth2User.getAttributes());
		// 2.
		System.out.println("oAuth2User: " + oAuth2User2.getAttributes());
		return "OAuth 세션 정보 확인 수행";
	}

	// localhost:8080/
	// localhost:8080
	@GetMapping({"","/"})
	public String index() {
		// 머스테치 기본폴더: scr/main/resources/
		// 뷰리졸버 설정: templates(prefix), .mustache(suffix)
		return "index"; // src/main/resources/templates/index.mustache
	}

	// UserDetails, OAuth2User 모두 받을 수 있다.
	@GetMapping("/user")
	public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
		System.out.println("principalDetails: " + principalDetails.getUser());
		return "user";
	}
	
	@GetMapping("/admin")
	public @ResponseBody String admin() {
		return "admin";
	}
	
	@GetMapping("/manager")
	public @ResponseBody String manager() {
		return "manager";
	}
	
	// 기본적으로 /login, /logout은 스프링 시큐리티가 인터셉트함, 하지만 지금은 SecurityConfig 설정으로 인해 정상 작동
	@PostMapping("/login")
	public String login() {
		return "login";
	}
	
	@GetMapping("/loginForm")
	public String loginForm() {
		return "loginForm";
	}
	
	@PostMapping("/join")
	public String join(User user) {
		user.setRole("ROLE_USER");
		String rawPassword = user.getPassword();
		String encPassword = bCryptPasswordEncoder.encode(rawPassword);
		user.setPassword(encPassword);
		userRepository.save(user); // 회원가입 잘됨. 비밀번호: 1234 => 시큐리티로 로그인 불가능: 패스워드 암호화가 안됐기 때문
		return "redirect:/loginForm";
	}
	
	@GetMapping("/joinForm")
	public String joinForm() {
		return "joinForm";
	}
	
	@GetMapping("/joinProc")
	public @ResponseBody String joinProc() {
		return "회원가입 완료됨!";
	}
	
	@Secured("ROLE_ADMIN") // 권한 조건 하나 걸기
	@GetMapping("/info")
	public @ResponseBody String info() {
		return "개인정보";
	}
	
	@PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')") // 권한 조건 여러 개 걸기, @PostAutorize도 있지만 잘 사용 안함
	@GetMapping("/data")
	public @ResponseBody String data() {
		return "데이터정보";
	}
}
