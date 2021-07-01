package wf.garnier.oauth2example.saml;

import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import wf.garnier.oauth2example.CustomAuthentication;

public class CustomSamlAuthentication extends Saml2Authentication implements CustomAuthentication {

	private final String providerName;
	private final int numberOfStars;
	private final boolean isAdmin = false;

	public CustomSamlAuthentication(
			Saml2AuthenticationToken saml2AuthenticationToken,
			Saml2Authentication parentAuthentication
	) {
		super((Saml2AuthenticatedPrincipal) parentAuthentication.getPrincipal(), parentAuthentication.getSaml2Response(), parentAuthentication.getAuthorities());
		Saml2AuthenticatedPrincipal samlPrincipal = (Saml2AuthenticatedPrincipal) parentAuthentication.getPrincipal();
		providerName = saml2AuthenticationToken.getRelyingPartyRegistration().getRegistrationId();
		Integer numberOfStars = samlPrincipal.getFirstAttribute("number_of_stars");
		this.numberOfStars = numberOfStars != null ? numberOfStars : 0;
	}

	@Override
	public String getProviderName() {
		return providerName;
	}

	@Override
	public int getNumberOfStars() {
		return numberOfStars;
	}

	@Override
	public boolean isAdmin() {
		return isAdmin;
	}
}
