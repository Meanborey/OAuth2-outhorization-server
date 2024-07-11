package com.example.oauth2authorizationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.time.Duration;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        var registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("kangchi")
                .clientSecret("{bcrypt}$2a$12$4U3GR70Y.rAumsMxoxU.3.DL2r/82her/UEfVM2weGQ0mbg08s79C")
                .scope("openid")
                .redirectUri("http://localhost:8080/login/oauth2/code/kangchi")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenSettings(tokenSettings())
                .clientSettings(clientSettings())
                .build();
        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    @Order(1)
    public SecurityFilterChain websecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());
        http.exceptionHandling(c -> c.defaultAuthenticationEntryPointFor(
                new LoginUrlAuthenticationEntryPoint("/login"),
                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
        ));
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain appsecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .authorizeRequests()
                .antMatchers("/auth/basic/endpoints/**", "/basic-auth/**").authenticated()
                .and()
                .httpBasic()
                .and()
                .authorizeRequests()
                .antMatchers(HttpMethod.POST, "/auth/oauth2/test/**").hasAnyAuthority("SCOPE_somescope/test")
                .antMatchers(HttpMethod.POST, "/auth/oauth2/other/**").hasAnyAuthority("SCOPE_somescope/other")
                .and()
                .oauth2ResourceServer().jwt().decoder(jwtDecoder())
                .and()
                .accessDeniedHandler(accessDeniedHandler())
                .and()
                .authorizeRequests()
                .anyRequest().permitAll()
                .and()
                .csrf().disable()
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated())
                .formLogin(Customizer.withDefaults());
        return httpSecurity.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager userDetailsManager = new InMemoryUserDetailsManager();
        userDetailsManager.createUser(User
                .withUsername("user")
                .password(passwordEncoder().encode("password"))
                .roles("USER")
                .build());
        return userDetailsManager;
    }

    public TokenSettings tokenSettings() {
        return TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                .accessTokenTimeToLive(Duration.ofHours(1))
                .reuseRefreshTokens(true)
                .refreshTokenTimeToLive(Duration.ofHours(7))
                .build();
    }

    public ClientSettings clientSettings() {
        return ClientSettings.builder()
                .requireAuthorizationConsent(true)
                .requireProofKey(true)
                .build();
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

//    @Bean
//    public WebMvcConfigurer corsConfigurer() {
//        return new WebMvcConfigurerAdapter() {
//            @Override
//            public void addCorsMappings(CorsRegistry registry) {
//                registry.addMapping("/**").allowedMethods("GET", "POST", "PUT", "DELETE").allowedOrigins("*")
//                        .allowedHeaders("*");
//            }
//        };
//    }

    // Add the jwtDecoder bean if not already defined
    @Bean
    public JwtDecoder jwtDecoder() {
        return JwtDecoders.fromIssuerLocation("http://localhost:8080");
    }

    // Add a custom access denied handler if not already defined
    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return new AccessDeniedHandlerImpl();
    }


//
//    @Bean
//    public RegisteredClientRepository registeredClientRepository() {
//        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId("web-client")
//                .clientSecret("{noop}secret") // Use appropriate password encoder
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
//                .scope(OidcScopes.OPENID)
//                .scope("message.read")
//                .scope("message.write")
//                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
//                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(10)).build())
//                .build();
//
//        return new InMemoryRegisteredClientRepository(registeredClient);
//    }
//
//    @Bean
//    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
//        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer<>();
//
//        http
//                .apply(authorizationServerConfigurer)
//                .and() // This `and()` is used to chain the next configuration
//                .formLogin(Customizer.withDefaults()); // This enables form login with default settings
//
//        return http.build();
//    }
//    private String password = "12345";
//
//    @Bean
//    @Order(1)
//    public SecurityFilterChain webSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
//
//        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);
//
//        httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
//
//                // TODO: Custom OAuth 2.0 consent page
//                /*.authorizationEndpoint(endpoint -> endpoint
//                        .consentPage("/oauth2/consent"))*/
//
//                // TODO: Custom password grant_type
//                /*.tokenEndpoint(token -> token
//                        .accessTokenRequestConverter(new CustomPasswordAuthenticationConverter())
//                        .authenticationProvider(new CustomPasswordAuthenticationProvider(jpaOAuth2AuthorizationService, tokenGenerator(), userDetailsService, passwordEncoder))
//                        .accessTokenRequestConverters(getConverters())
//                        .authenticationProviders(getProviders()))*/
//
//                // TODO: Using default OpenID Connect
//                .oidc(Customizer.withDefaults());
//        // TODO: Exception happens will redirect to `/login`
//        httpSecurity.exceptionHandling(
//                c -> c.defaultAuthenticationEntryPointFor(
//                        new LoginUrlAuthenticationEntryPoint("/login"),
//                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
//                )
//        );
//
//        // TODO: Accept access tokens for user info and/or client registration
//        // httpSecurity.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
//
//        return httpSecurity.build();
//    }
////    @Bean
////    @Order(2)
////    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
////        http.authorizeHttpRequests(auth -> auth
////                .requestMatchers("/public").permitAll()
////                .anyRequest().authenticated());
////
////        http.formLogin(Customizer.withDefaults());
////        return http.build();
////    }
//
//    @Bean
//    @Order(2)
//    public SecurityFilterChain appSecurity(HttpSecurity httpSecurity) throws Exception {
//
//        httpSecurity
//                .authorizeHttpRequests(auth -> auth
//                        //.requestMatchers("/login", "/error").permitAll() // TODO: Need if you custom form login
//                        .anyRequest().authenticated())
//
//                // TODO: implement default form login
//                .formLogin(Customizer.withDefaults());
//
//        // TODO: Custom form login
//        // .formLogin(login -> login.loginPage("/login"));
//
//        return httpSecurity.build();
//    }
//
//    @Bean
//    public UserDetailsService userDetailsService() {
//        InMemoryUserDetailsManager users = new InMemoryUserDetailsManager();
////      users.createUser(User.withUsername("user")
//////              .password("{Bcrypt}$2a$12$gdtaPLh2k5piLdQJJNXMH.L38tO8WlPov0gzrNVJrgacQxDOFq01e")
////              .password(passwordEncoder().encode(password))
////              .authorities("read")
////              .build());
//      users.createUser(User.withUsername("admin")
////              .password("{Bcrypt}$2a$12$gdtaPLh2k5piLdQJJNXMH.L38tO8WlPov0gzrNVJrgacQxDOFq01e")
//              .password("{noop}kangchi")
//              .authorities("read", "write")
//              .build());
//        return users;
////        UserDetails userDetails = User.withDefaultPasswordEncoder()
////                .username("user")
////                .password("password")
////                .roles("USER")
////                .build();
////        return new InMemoryUserDetailsManager(userDetails);
//    }
//
//    @Bean
//    public RegisteredClientRepository registeredClientRepository() {
//        var registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId("kangchi")
//                    .clientSecret("{bcrypt}$2a$12$4U3GR70Y.rAumsMxoxU.3.DL2r/82her/UEfVM2weGQ0mbg08s79C") // store in secret manager
//                .scopes(scopes -> {
//                    scopes.add("openid");
////                    scopes.add("profile");
////                    scopes.add("email");
////                    scopes.add("phone");
////                    scopes.add("address");
//                    //scopes.add("keys.write");
//                })
////                .redirectUri("https://meanborey-profile.vercel.app")
//                .redirectUri("http://localhost:8080/login/oauth2/code/kangchi")
////                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE) // public client - PKCE
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                // grant_type:client_credentials, client_id & client_secret, redirect_uri
////                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
////                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
//                .authorizationGrantTypes(
//                        grantType -> {
//                            grantType.add(AuthorizationGrantType.AUTHORIZATION_CODE);
//                            grantType.add(AuthorizationGrantType.REFRESH_TOKEN);
//                            grantType.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
//                            //grantType.add(new AuthorizationGrantType("custom_password"));
//                        }
//                )
//                .tokenSettings(tokenSettings())
//                .clientSettings(clientSettings())
//                .build();
//
//        return new InMemoryRegisteredClientRepository(registeredClient);
//    }
//
//    public TokenSettings tokenSettings() {
//        return TokenSettings.builder()
//                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
//                .accessTokenTimeToLive(Duration.ofDays(1))
//                .reuseRefreshTokens(true)
//                .refreshTokenTimeToLive(Duration.ofDays(7))
//                .build();
//    }
//
//    public ClientSettings clientSettings() {
//        return ClientSettings.builder()
//                .requireAuthorizationConsent(true)
//                .requireProofKey(true)
//                .build();
//    }
//
//    @Bean
//    public AuthorizationServerSettings authorizationServerSettings() {
//        return AuthorizationServerSettings.builder().build();
//    }



//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }


//    @Bean
//    public JWKSource<SecurityContext>jwkSource() throws NoSuchAlgorithmException {
//        KeyPairGenerator keyPairGenerator= KeyPairGenerator.getInstance("RSA");
//        keyPairGenerator.initialize(2048);
//        var keyPair = keyPairGenerator.generateKeyPair();
//        var publicKey = (RSAPublicKey) keyPair.getPublic();
//        var privateKey = keyPair.getPrivate();
//
//        var rsaKey =  new RSAKey.Builder(publicKey)
//                .privateKey(privateKey)
//                .keyID(UUID.randomUUID().toString())
//                .build();
//
//        JWKSet jwkSet = new JWKSet(rsaKey);
//        return (jwkSelector, context) -> jwkSelector.select(jwkSet);
//    }
//
//    @Bean
//    OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator() {
//
////        System.out.println("KANGCHI => Start Generate Token");
//
//        NimbusJwtEncoder jwtEncoder = null;
//
//        try {
//            jwtEncoder = new NimbusJwtEncoder(jwkSource());
//        } catch (NoSuchAlgorithmException e) {
//            throw new RuntimeException(e);
//        }
//
//        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
//        jwtGenerator.setJwtCustomizer(tokenCustomizer());
//        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
//        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
//
//        return new DelegatingOAuth2TokenGenerator(
//                jwtGenerator, accessTokenGenerator, refreshTokenGenerator
//        );
//    }
//    @Bean
//    OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
//        return context -> {
//
//            // TODO: Custom JWT with authorization_code grant type and Authentication
//            Authentication authentication = context.getPrincipal();
//            if (context.getTokenType().getValue().equals("id_token")) {
//                context.getClaims().claim("skyvva", "salesforce");
//            }
//
//            if (context.getTokenType().getValue().equals("access_token")) {
//                Set<String> authorities = authentication.getAuthorities().stream()
//                        .map(GrantedAuthority::getAuthority)
//                        .collect(Collectors.toSet());
//                context.getClaims().claim("authorities", authorities)
//                        .claim("user", authentication.getName());
//            }
//        };
//    }
}
