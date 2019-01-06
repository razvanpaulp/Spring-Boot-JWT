package code.project.springbootjwt.security;


import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static code.project.springbootjwt.security.SecurityConstants.EXPIRATION_TIME;
import static code.project.springbootjwt.security.SecurityConstants.HEADER_STRING;
import static code.project.springbootjwt.security.SecurityConstants.SECRET;
import static code.project.springbootjwt.security.SecurityConstants.TOKEN_PREFIX;


public class JWTAuthorizationFilter extends AbstractAuthenticationProcessingFilter {

    public JWTAuthorizationFilter(AuthenticationManager authManager) {
        super("/");
    }
    
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		
		 String header = request.getHeader(HEADER_STRING);

	        if (header == null || !header.startsWith(TOKEN_PREFIX)) {
	            return new BearerToken();
	        }

	        BearerToken authentication = getAuthentication(request);

			return authentication;
	}


    private BearerToken getAuthentication(HttpServletRequest request) {
        String token = request.getHeader(HEADER_STRING);
        if (token != null) {
        	boolean validToken = validateJwtToken(token);

            if (validToken) {
                return new BearerToken(token);
            }
            return null;
        }
        return null;
    }
    
    @Override
    protected final void successfulAuthentication(HttpServletRequest request,
                                                  HttpServletResponse response, FilterChain chain, Authentication authResult)
            throws IOException, ServletException {

        if (logger.isDebugEnabled()) {
            logger.debug("Authentication success. Updating SecurityContextHolder to contain: "
                    + authResult);
        }

        SecurityContextHolder.getContext().setAuthentication(authResult);

        Cookie jwtAuthenticationCookie = createJWTAuthenticationCookie((String) authResult.getPrincipal());
        response.addCookie(jwtAuthenticationCookie);
        chain.doFilter(request, response);
    }
    
    @Override
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        return !authenticated(request) && request.getHeader(HEADER_STRING) != null;
    }
    
    /**
     * Determines if a user is already authenticated.
     * @return
     */
    private boolean authenticated(HttpServletRequest request) {
        //get JWT cookie
        return true;
    }
    
    private Cookie createJWTAuthenticationCookie( String token) {
        final String jwtToken  = token;
        final Cookie cookie = new Cookie(HttpHeaders.AUTHORIZATION, "Bearer " + jwtToken);
        cookie.setHttpOnly(true);

        return cookie;
    }
    
    private boolean validateJwtToken(String token) {
    	return true;
    }



}