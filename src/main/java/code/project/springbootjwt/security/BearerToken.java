package code.project.springbootjwt.security;


import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class BearerToken extends AbstractAuthenticationToken{

	private static final long serialVersionUID = 1L;
	private final Object bearer;

	public BearerToken() {
		super(null);
		this.bearer = null;
		setAuthenticated(false);
	}
	
	public BearerToken(Object token) {
		super(null);
		this.bearer = token;
		setAuthenticated(true);
	}

	@Override
	public Object getCredentials() {
		return bearer;
	}

	@Override
	public Object getPrincipal() {
		return bearer;
	}

}
