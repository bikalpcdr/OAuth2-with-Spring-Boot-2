package com.OAuth2.dto;

import lombok.Data;

import java.util.Set;

@Data
public class UserDTO {
    private String username;
    private String email;
    private String password;
    private Set<String> roles;
}