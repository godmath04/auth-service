package com.portalperiodistico.auth_service.service;

import com.portalperiodistico.auth_service.domain.entity.User;
import com.portalperiodistico.auth_service.domain.repository.UserRepository;
import com.portalperiodistico.auth_service.security.UserPrincipal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // 1. Busca el usuario en nuestra BD
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado: " + username));

        // 2. Retorna nuestro UserPrincipal (que implementa UserDetails)
        return new UserPrincipal(user);
    }
}