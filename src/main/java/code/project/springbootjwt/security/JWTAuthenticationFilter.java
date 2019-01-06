package code.project.springbootjwt.security;

import static code.project.springbootjwt.security.SecurityConstants.EXPIRATION_TIME;
import static code.project.springbootjwt.security.SecurityConstants.HEADER_STRING;
import static code.project.springbootjwt.security.SecurityConstants.SECRET;
import static code.project.springbootjwt.security.SecurityConstants.TOKEN_PREFIX;

import java.io.IOException;
import java.security.Key;
import java.util.Date;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;


public class JWTAuthenticationFilter extends BasicAuthenticationFilter {

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
       super(authenticationManager);
    }


    @Override
    protected void onSuccessfulAuthentication(HttpServletRequest req,
                                            HttpServletResponse res,
                                            Authentication auth) throws IOException {

        String token = generateToken((User) auth.getPrincipal(), new Date(System.currentTimeMillis() + EXPIRATION_TIME));
        res.addHeader(HEADER_STRING, TOKEN_PREFIX + token);

    }
    

    
    private String generateToken(final User user, Date expirationDate) {
        String compactJws = Jwts.builder()
                .setSubject(user.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(expirationDate)
                //.setClaims()
                .signWith(SignatureAlgorithm.HS512, SECRET.getBytes())
                .compact();

        return compactJws;
    }
}