package com.kot.security1.config.oauth;

import com.kot.security1.config.auth.PrincipalDetails;
import com.kot.security1.config.oauth.provider.FacebookUserInfo;
import com.kot.security1.config.oauth.provider.GoogleUserInfo;
import com.kot.security1.config.oauth.provider.OAuth2UserInfo;
import com.kot.security1.model.User;
import com.kot.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class PrincipalOAuth2UserService extends DefaultOAuth2UserService {
    @Autowired
    private UserRepository userRepository;
//    @Autowired
//    private BCryptPasswordEncoder bCryptPasswordEncoder;

    // Google로부터 받은 userRequest 데이터에 대한 후처리를 수행하는 함수
    // 함수 종료시 @AuthenticationPrincipal이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("getClientRegistration: " + userRequest.getClientRegistration()); // registrationId로 어떤 OAuth로 로그인했는지 확인 가능
        System.out.println("getAccessToken: " + userRequest.getAccessToken().getTokenValue()); //

        OAuth2User oAuth2User = super.loadUser(userRequest);
        // 구글 로그인 버튼 클릭 -> 구글 로그인 창 -> 로그인 완료 -> code 리턴(OAuth-Client 라이브러리) -> AccessToken 요청
        // userRequest정보 -> loadUSer 함수 -> 구글로부터 회원 프로필 받음
        System.out.println("getAttributes: " + oAuth2User.getAttributes());

        // 회원가입 진행
        OAuth2UserInfo oAuth2UserInfo = null;
        // provider: google
        if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            System.out.println("구글 로그인 요청");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        // provider: facebook
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
            System.out.println("페이스북 로그인 요청");
            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
        } else {
            System.out.println("우리는 구글과 페이스북만 지원해요...");
        }
        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId;
        String password = "getinthere";
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(username);
        if (userEntity == null) {
            System.out.println(provider + " 로그인이 최초입니다.");
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        } else {
            System.out.println(provider + "로그인을 이미 한적이 있습니다. 당신은 자동 회원 가입이 되어 있습니다.");
        }
        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
