package wf.garnier.oauth2example.saml;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;

public class CustomSamlAuthenticationProvider implements AuthenticationProvider {

	private final OpenSamlAuthenticationProvider delegate;

	public CustomSamlAuthenticationProvider() {
		this.delegate = new OpenSamlAuthenticationProvider();
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		Authentication authenticationResult = this.delegate.authenticate(authentication);
		return new CustomSamlAuthentication((Saml2AuthenticationToken) authentication, (Saml2Authentication) authenticationResult);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return delegate.supports(authentication);
	}
}
