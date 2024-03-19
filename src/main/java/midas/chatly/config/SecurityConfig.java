package midas.chatly.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import midas.chatly.jwt.filter.JwtAuthenticationProcessingFilter;
import midas.chatly.jwt.service.JwtService;
import midas.chatly.login.filter.CustomJsonUsernamePasswordAuthenticationFilter;
import midas.chatly.login.handler.LoginFailureHandler;
import midas.chatly.login.handler.LoginSuccessHandler;
import midas.chatly.login.service.LoginService;
import midas.chatly.oauth.handler.OAuth2LoginFailureHandler;
import midas.chatly.oauth.handler.OAuth2LoginSuccessHandler;
import midas.chatly.oauth.service.CustomOAuth2UserService;
import midas.chatly.redis.repository.RefreshTokenRepository;
import midas.chatly.repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;


@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final LoginService loginService;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final ObjectMapper objectMapper;
    private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
    private final OAuth2LoginFailureHandler oAuth2LoginFailureHandler;
    private final CustomOAuth2UserService customOAuth2UserService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf((auth) -> auth.disable())
                .cors()
                .and()
                .formLogin((auth) -> auth.disable());

        http
                .httpBasic((auth) -> auth.disable());
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/**").permitAll()
                        .anyRequest().authenticated());
        http
                .oauth2Login((oauth2) -> oauth2
                        .loginPage("/login")
                        .successHandler(oAuth2LoginSuccessHandler)
                        .failureHandler(oAuth2LoginFailureHandler)
                        .userInfoEndpoint((userInfoEndpointConfig) -> userInfoEndpointConfig
                                .userService(customOAuth2UserService)));

        http.addFilterAfter(customJsonUsernamePasswordAuthenticationFilter(), LogoutFilter.class);
        http.addFilterBefore(jwtAuthenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder());
        provider.setUserDetailsService(loginService);

        return new ProviderManager(provider);
    }

    @Bean
    public LoginSuccessHandler loginSuccessHandler() {
        return new LoginSuccessHandler(jwtService, userRepository,refreshTokenRepository);
    }

    @Bean
    public AuthenticationFailureHandler loginFailureHandler() {
        return new LoginFailureHandler();
    }

    @Bean
    public CustomJsonUsernamePasswordAuthenticationFilter customJsonUsernamePasswordAuthenticationFilter() {
        CustomJsonUsernamePasswordAuthenticationFilter customJsonUsernamePasswordLoginFilter
                = new CustomJsonUsernamePasswordAuthenticationFilter(objectMapper, userRepository);
        customJsonUsernamePasswordLoginFilter.setAuthenticationManager(authenticationManager());
        customJsonUsernamePasswordLoginFilter.setAuthenticationSuccessHandler(loginSuccessHandler());
        customJsonUsernamePasswordLoginFilter.setAuthenticationFailureHandler(loginFailureHandler());
        return customJsonUsernamePasswordLoginFilter;
    }

    @Bean
    public Filter jwtAuthenticationProcessingFilter() {
        JwtAuthenticationProcessingFilter jwtAuthenticationFilter = new JwtAuthenticationProcessingFilter(jwtService, userRepository);
        return jwtAuthenticationFilter;
    }

}
