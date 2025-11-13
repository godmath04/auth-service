package com.portalperiodistico.auth_service.service;

import com.portalperiodistico.auth_service.domain.entity.User;
import com.portalperiodistico.auth_service.domain.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // 1. Busca el usuario en nuestra BD usando el repositorio
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado: " + username));

        // 2. Convierte nuestros Roles (entidad) a GrantedAuthority (Spring Security)
        Set<GrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getRoleName()))
                .collect(Collectors.toSet());

        // 3. Retorna el objeto UserDetails que Spring Security entiende
        //    Usamos el constructor completo para verificar el estado de la cuenta.
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPasswordHash(), // Importante: pasamos el hash de la BD
                user.isActive(),        // true si la cuenta está activa
                true,                   // true: cuenta no expirada
                true,                   // true: credenciales no expiradas
                true,                   // true: cuenta no bloqueada
                authorities             // La lista de roles
        );
    }
}