package com.portalperiodistico.auth_service.dto;

import lombok.Data;

@Data
public class RegisterRequest {
    private String username;
    private String password;
    private String email;
    private String firstName;
    private String lastName;
    // Opcional: Podríamos añadir un Set<String> roles si
    // quisiéramos que el admin asigne roles al crear
}