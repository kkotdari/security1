package com.kot.security1.config.auth;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.kot.security1.model.User;
import org.springframework.security.oauth2.core.user.OAuth2User;

import javax.management.loading.PrivateClassLoader;

// /login 주소 요청이 오면 시큐리티가 낚아채서 로그인을 진행시킨다.
// 로그인 진행이 완료되면 시큐리티 session을 만들어줍니다. (Security ContextHolder)
// 시큐리티 session에 들어갈 수 있는 오브젝트 => Authentication 타입 객체
// Authentication 안에 User 정보가 있어야 함.
// User 오브젝트 타입 => UserDetails 타입 객체

// Security Session => Authentication => UserDetails(PrincipalDetails)

@Getter
public class PrincipalDetails implements UserDetails, OAuth2User {
	private User user; // 콤포지션
	private Map<String, Object> attributes;

	// 생성자: 일반 로그인
	public PrincipalDetails(User user) {
		this.user = user;
	}

	// 생성자: OAuth 로그인
	public PrincipalDetails(User user, Map<String, Object> attributes) {
		this.user = user;
		this.attributes = attributes;
	}

	// 해당 User의 권한을 리턴하는 메서드
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		Collection<GrantedAuthority> collect = new ArrayList<>();
		collect.add(new GrantedAuthority() {
			@Override
			public String getAuthority() {
				return user.getRole();
			}
		});
		return collect;
	}

	@Override
	public String getPassword() {
		return user.getPassword();
	}

	@Override
	public String getUsername() {
		return user.getUsername();
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		// 사용 예시: 사이트에 1년 동안 접속을 안하면 휴면 계정이 된다
		/* 
		 * 현재 시간 - 마지막 로그인 시간 > 1년
		 * 활성화 변경
		 */
		return true;
	}

	@Override
	public Map<String, Object> getAttributes() {
		return null;
	}

	@Override
	public String getName() {
		return null;
	}
}
