package com.OAuth2.controller;


import com.OAuth2.config.RevokeTokenService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/oauth/token")
public class TokenController  {
    private final RevokeTokenService revokeTokenService;

    public TokenController(RevokeTokenService revokeTokenService) {
        this.revokeTokenService = revokeTokenService;
    }


    @PostMapping("/revoke/{clientId}/{userName}")
    public ResponseEntity<?> revokeToken(@PathVariable String clientId, @PathVariable String userName){
        revokeTokenService.removeAccessToken(clientId,userName);
        return ResponseEntity.ok("Success");
    }
}
