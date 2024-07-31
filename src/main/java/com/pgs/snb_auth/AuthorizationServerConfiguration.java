package com.pgs.snb_auth;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * @author Attoumane AHAMADI
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfiguration {

  @Autowired(required = false)
  PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

  @Bean
  public SecurityFilterChain authorizationServerSecurityFilterChain(
          HttpSecurity http,
          UserDetailsService userDetailsService,
          OAuth2AuthorizationService authorizationService,
          OAuth2TokenGenerator<?> tokenGenerator) throws Exception {

    OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
            new OAuth2AuthorizationServerConfigurer();

    authorizationServerConfigurer
            .tokenEndpoint(tokenEndpoint ->
                    tokenEndpoint
                            .accessTokenRequestConverter(
                                    new OAuth2PasswordGrantAuthenticationConverter())
                            .authenticationProvider(
                                    new OAuth2PasswordGrantAuthenticationProvider(userDetailsService, passwordEncoder, authorizationService, tokenGenerator)));

    RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

    http
            .securityMatcher(endpointsMatcher)
            .authorizeHttpRequests(authorize ->
                    authorize
                            .anyRequest().authenticated()
            )
            .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
            .apply(authorizationServerConfigurer);

    return http.build();


  }

  @Bean
  public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
//     RegisteredClient messagingClient = RegisteredClient.withId(UUID.randomUUID().toString())
//             .clientId("messaging-client")
//             .clientSecret("{noop}secret")
//             .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//             .authorizationGrantType(new AuthorizationGrantType("password"))
//             .authorizationGrantType(new AuthorizationGrantType("client_credentials"))
//             .scope("message.read")
//             .scope("message.write")
//             .build();

        RegisteredClient messagingClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("messaging-client")
				.clientSecret("{noop}secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                                .authorizationGrantType(new AuthorizationGrantType("password"))
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
				.redirectUri("http://127.0.0.1:8080/authorized")
				.postLogoutRedirectUri("http://127.0.0.1:8080/logged-out")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.scope("message.read")
				.scope("message.write")
				.scope("user.read")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build();
                                
        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);

        RegisteredClient  existingClient = registeredClientRepository.findByClientId("messaging-client");
        if(existingClient == null) {
            registeredClientRepository.save(messagingClient);
        }

    return registeredClientRepository;
  }



  @Bean
        public JdbcOAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate,
                        RegisteredClientRepository registeredClientRepository) {
                return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
        }


        

        @Bean
        public JdbcOAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate,
                        RegisteredClientRepository registeredClientRepository) {
                return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
        }

  @Bean
  OAuth2TokenGenerator<?> tokenGenerator(JWKSource<SecurityContext> jwkSource, OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer) {
    JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
    jwtGenerator.setJwtCustomizer(oAuth2TokenCustomizer);
    OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
    OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
    return new DelegatingOAuth2TokenGenerator(
            jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
  }

  // https://github.com/spring-projects/spring-authorization-server/issues/502#issuecomment-971731130

  @Bean
  public OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer() {
    return context -> {
      if (AuthorizationGrantType.PASSWORD.equals(context.getAuthorizationGrantType()) &&
              OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
        Authentication principal = context.getPrincipal();
        Set<String> authorities = new HashSet<>();
        for (GrantedAuthority authority : principal.getAuthorities()) {
          authorities.add(authority.getAuthority());
        }
        context.getClaims().claim("authorities", authorities);
        
        // set additional claims
        Set<String> privileges = new HashSet<>();
        privileges.add("READ_AUCTION");
        privileges.add("RESEND_ACTIVATION_LINK");
        context.getClaims().claim("privileges", privileges);
      }
    };
  }
}
