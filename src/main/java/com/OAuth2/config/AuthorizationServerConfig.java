package com.OAuth2.config;


import com.OAuth2.customUserDetailsService.CustomUserDetailsService;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import javax.sql.DataSource;
import java.security.KeyPair;

@Configuration
@EnableAuthorizationServer
@EnableConfigurationProperties(SecurityProperties.class)
public class AuthorizationServerConfig implements AuthorizationServerConfigurer {
    /**
     * DataSource represents a database connection source that allows you to connect to a database and execute SQL queries.
     */
    private final DataSource dataSource;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final CustomUserDetailsService userDetailsService;
    private final SecurityProperties securityProperties;
    private JwtAccessTokenConverter jwtAccessTokenConverter;
    private TokenStore tokenStore;

    public AuthorizationServerConfig(final DataSource dataSource,
                                     final PasswordEncoder passwordEncoder,
                                     final AuthenticationManager authenticationManager,
                                     final CustomUserDetailsService userDetailsService,
                                     final SecurityProperties securityProperties) {
        this.dataSource = dataSource;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.securityProperties = securityProperties;
    }
    /**
     * manage and store OAuth 2.0 tokens.
     * @return
     */
    @Bean
    public TokenStore tokenStore() {
//        if (tokenStore == null) {
//            tokenStore = new JwtTokenStore(jwtAccessTokenConverter());
//        }
        return new JdbcTokenStore(dataSource);
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer
                .passwordEncoder(this.passwordEncoder)  //password encoder bean that is responsible for encoding and decoding passwords securely
                /**
                 *  This configuration allows anyone, even people who haven't logged in, to access a special endpoint where the server's public key is stored
                 *  This public key is used by applications to make sure that the tokens they receive from the server are genuine.
                 */
                .tokenKeyAccess("permitAll()")
                /**
                 * This configuration controls who can check if a token (like a login or access token) is valid.
                 * When you set it to "isAuthenticated," it means only people who have already logged in and have a valid token can use this feature.
                 */
                .checkTokenAccess("isAuthenticated()");

    }

    /**
     * @param clients
     * @throws Exception
     * ClientDetailsServiceConfigurer is a class provided by Spring Security that allows you to configure OAuth 2.0 clients.
     * client represents an application or service that wants to access protected resources
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        /**
         * This method configures the ClientDetailsServiceConfigurer to use the specified data source to fetch client details.
         * client details, such as client IDs, client secrets, and other client-specific information from database
         */
        clients.jdbc(this.dataSource);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .pathMapping("/oauth/token", "/ins/login") //maps the endpoint "/oauth/token" to a different endpoint, "/abs/login."
                .authenticationManager(authenticationManager)
                .accessTokenConverter(jwtAccessTokenConverter())
                .reuseRefreshTokens(false)
                .userDetailsService(userDetailsService)
                .tokenStore(tokenStore());
    }


    @Bean
    @Primary
    public DefaultTokenServices tokenServices(final TokenStore tokenStore,
                                              final ClientDetailsService clientDetailsService) {
        DefaultTokenServices tokenServices = new DefaultTokenServices();
        tokenServices.setSupportRefreshToken(true); //When set to true, it allows refresh tokens to be used more than once to obtain new access tokens.
        tokenServices.setTokenStore(tokenStore); //token store is responsible for storing, retrieving, and managing access and refresh tokens.
        tokenServices.setClientDetailsService(clientDetailsService);
        tokenServices.setAuthenticationManager(this.authenticationManager);
        return tokenServices;
    }


    /**
     * will create jwt token for authorization server
     * this bean is used to convert OAuth 2.0 access tokens to JWT (JSON Web Tokens) format.
     * @return
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        if (jwtAccessTokenConverter != null) {
            return jwtAccessTokenConverter;
        }

        SecurityProperties.JwtProperties jwtProperties = securityProperties.getJwt();
        KeyPair keyPair = keyPair(jwtProperties, keyStoreKeyFactory(jwtProperties));

        jwtAccessTokenConverter = new JwtAccessTokenConverter();
        jwtAccessTokenConverter.setKeyPair(keyPair);
        return jwtAccessTokenConverter;
    }

    private KeyPair keyPair(SecurityProperties.JwtProperties jwtProperties, KeyStoreKeyFactory keyStoreKeyFactory) {
        return keyStoreKeyFactory.getKeyPair(jwtProperties.getKeyPairAlias(), jwtProperties.getKeyPairPassword().toCharArray());
    }

    private KeyStoreKeyFactory keyStoreKeyFactory(SecurityProperties.JwtProperties jwtProperties) {
        return new KeyStoreKeyFactory(jwtProperties.getKeyStore(), jwtProperties.getKeyStorePassword().toCharArray());
    }
}
