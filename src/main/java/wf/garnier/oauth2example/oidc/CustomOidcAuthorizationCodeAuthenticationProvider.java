package wf.garnier.oauth2example.oidc;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;

public class CustomOidcAuthorizationCodeAuthenticationProvider extends OidcAuthorizationCodeAuthenticationProvider {
	public CustomOidcAuthorizationCodeAuthenticationProvider() {
		super(new DefaultAuthorizationCodeTokenResponseClient(), new OidcUserService());
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2LoginAuthenticationToken result = (OAuth2LoginAuthenticationToken) super.authenticate(authentication);
		return new CustomOAuth2LoginAuthenticationToken(result);
	}
}
