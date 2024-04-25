package org.example.oauthsession.service;

import lombok.RequiredArgsConstructor;
import org.example.oauthsession.dto.CustomOauth2User;
import org.example.oauthsession.dto.GoogleResponse;
import org.example.oauthsession.dto.NaverResponse;
import org.example.oauthsession.dto.OAuth2Response;
import org.example.oauthsession.entity.UserEntity;
import org.example.oauthsession.repository.UserRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomOauth2UserService extends DefaultOAuth2UserService {
    //DefaultOAuth2UserService OAuth2UserService의 구현체

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println(oAuth2User.getAttributes());

        String registrationId = userRequest
                .getClientRegistration()
                .getRegistrationId();
        OAuth2Response oAuth2Response = null;
        if (registrationId.equals("naver")) {
            oAuth2Response = new NaverResponse(oAuth2User.getAttributes());
        }
        else if (registrationId.equals("google")) {
            oAuth2Response = new GoogleResponse(oAuth2User.getAttributes());
        }
        else {

            return null;
        }

        String role = null;

        String username = oAuth2Response.getProvider()+ " " + oAuth2Response.getProviderId();

        UserEntity existData = userRepository.findByUsername(username);

        if(existData == null){

            UserEntity userEntity = new UserEntity();

            userEntity.setUsername(username);
            userEntity.setEmail(oAuth2Response.getEmail());
            userEntity.setRole("ROLE_USER");

            userRepository.save(userEntity);
        }else{
            role = existData.getRole();

            existData.setEmail(oAuth2Response.getEmail());
            existData.setRole(role);

            userRepository.save(existData);
        }


        return new CustomOauth2User(oAuth2Response, role);

        //추후 작성
    }

}
