package wf.garnier.oauth2example.oidc;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;

public class CustomOAuth2LoginAuthenticationFilter extends OAuth2LoginAuthenticationFilter {
	private final OAuth2AuthorizedClientRepository authorizedClientRepository;

	public CustomOAuth2LoginAuthenticationFilter(ClientRegistrationRepository clientRegistrationRepository, OAuth2AuthorizedClientRepository authorizedClientRepository, AuthenticationManager authenticationManager) {
		super(clientRegistrationRepository, authorizedClientRepository, DEFAULT_FILTER_PROCESSES_URI);
		super.setAuthorizationRequestRepository(new HttpSessionOAuth2AuthorizationRequestRepository());
		super.setAuthenticationManager(authenticationManager);
		this.authorizedClientRepository = authorizedClientRepository;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
		OAuth2AuthenticationToken oauth2Authentication = (OAuth2AuthenticationToken) super.attemptAuthentication(request, response);
		CustomOAuth2AuthenticationToken authenticationResult = new CustomOAuth2AuthenticationToken(oauth2Authentication);
		OAuth2AuthorizedClient authorizedClient = this.authorizedClientRepository.loadAuthorizedClient(
				oauth2Authentication.getAuthorizedClientRegistrationId(), oauth2Authentication, request);
		// ensure that our SSO authentication is what is stored
		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, authenticationResult, request, response);
		return authenticationResult;

	}
}
