package com.portalperiodistico.auth_service.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    // 1. Inyectaremos la clave secreta desde application.properties
    //    Esta clave es la "firma" de nuestros tokens.
    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration; // Tiempo de expiración en milisegundos

    // 2. Método principal para generar un nuevo token
    public String generateToken(UserDetails userDetails) {
        // Podemos añadir "claims" extra (información adicional) si quisiéramos
        Map<String, Object> claims = new HashMap<>();
        // Por ejemplo, podríamos añadir los roles
        // claims.put("roles", userDetails.getAuthorities());

        return buildToken(claims, userDetails, jwtExpiration);
    }

    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        return Jwts.builder()
                .setClaims(extraClaims) // Añade claims extra
                .setSubject(userDetails.getUsername()) // El "dueño" del token
                .setIssuedAt(new Date(System.currentTimeMillis())) // Cuándo se creó
                .setExpiration(new Date(System.currentTimeMillis() + expiration)) // Cuándo expira
                .signWith(getSigningKey(), SignatureAlgorithm.HS256) // Firma el token
                .compact();
    }

    // 3. Métodos para validar el token
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // 4. Métodos para extraer información del token
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject); // El "subject" es el username
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // 5. Métodos para manejar la clave secreta
    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}