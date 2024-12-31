package com.OAuth2.config;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

import javax.annotation.Resource;
import javax.transaction.Transactional;
import java.util.Collection;

@Component
@Transactional
public class RevokeTokenService {
    private final TokenStore tokenStore;

    public RevokeTokenService(TokenStore tokenStore){
        this.tokenStore = tokenStore;
    }

    @Resource(name = "tokenServices")
    private ConsumerTokenServices tokenServices;

    public void removeAccessToken(String clientId,String userName) {
        Collection<OAuth2AccessToken> clientInfo =
                tokenStore.findTokensByClientIdAndUserName(clientId, userName);
        if(!ObjectUtils.isEmpty(clientInfo)){
            clientInfo.forEach(m->
            tokenServices.revokeToken(m.getValue()));
        }else {
            throw new RuntimeException("Authentication is null");
        }
    }

}
