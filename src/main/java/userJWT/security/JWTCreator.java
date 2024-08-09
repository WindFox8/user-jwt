package userJWT.security;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

public class JWTCreator {

    private static final Key secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);  // Chave secreta para assinatura do token
    private static final long expiration = 1800000L; // Expiração de 30 minutos

    public static String create(JWTObject jwtObject) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", jwtObject.getRoles());
        
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(jwtObject.getSubject())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(secretKey)
                .compact();
    }

    public static JWTObject parse(String token) {
        var body = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        JWTObject jwtObject = new JWTObject();
        jwtObject.setSubject(body.getSubject());
        jwtObject.setRoles((List<String>) body.get("roles"));
        jwtObject.setExpiration(body.getExpiration().getTime());
        
        return jwtObject;
    }
}
