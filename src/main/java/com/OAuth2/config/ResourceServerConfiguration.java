package com.OAuth2.config;


import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * <p>
 * This configuration is used to access oauth sever resources using token or define open url.
 * </p>
 */
@Configuration
@EnableResourceServer
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableConfigurationProperties(SecurityProperties.class)
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {
    private static final String ROOT_PATTERN = "/**";
    /**
     * this is saved in oauth_client_detail table resource_ids
     * this means token generated from client can only access the resource for resource id inventory
     */
    private static final String RESOURCE_ID = "inventory";
    private final TokenStore tokenStore;
    private final SecurityProperties securityProperties;

    public ResourceServerConfiguration(TokenStore tokenStore, SecurityProperties securityProperties) {
        this.tokenStore = tokenStore;
        this.securityProperties = securityProperties;
    }

    @Override
    public void configure(final ResourceServerSecurityConfigurer resources) {
        resources.tokenStore(tokenStore).resourceId(RESOURCE_ID);
    }


    /**
     * here if the request is GET then it should have scope - READ and same for other HTTP methods
     * @param http
     * @throws Exception
     */
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/oauth/token/**").permitAll()
                .antMatchers(HttpMethod.GET,ROOT_PATTERN).access("#oauth2.hasScope('READ')")
                .antMatchers(HttpMethod.POST,ROOT_PATTERN).access("#oauth2.hasScope('WRITE')")
                .antMatchers(HttpMethod.PATCH,ROOT_PATTERN).access("#oauth2.hasScope('WRITE')")
                .antMatchers(HttpMethod.PUT,ROOT_PATTERN).access("#oauth2.hasScope('WRITE')")
                .antMatchers(HttpMethod.DELETE,ROOT_PATTERN).access("#oauth2.hasScope('WRITE')")
        ;
        http.csrf().disable();
    }


}