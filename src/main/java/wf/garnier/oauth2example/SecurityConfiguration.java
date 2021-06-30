package wf.garnier.oauth2example;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import wf.garnier.oauth2example.oidc.CustomOAuth2LoginAuthenticationFilter;
import wf.garnier.oauth2example.oidc.CustomOidcAuthorizationCodeAuthenticationProvider;
import wf.garnier.oauth2example.userdetails.CustomUserDetailsAuthenticationProvider;

@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	private final CustomUserDetailsAuthenticationProvider customUserDetailsAuthenticationProvider;
	private final ClientRegistrationRepository clientRegistrationRepository;
	private final OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;

	public SecurityConfiguration(
			CustomUserDetailsAuthenticationProvider customUserDetailsAuthenticationProvider,
			OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository,
			ClientRegistrationRepository clientRegistrationRepository) throws Exception {
		this.customUserDetailsAuthenticationProvider = customUserDetailsAuthenticationProvider;
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.oAuth2AuthorizedClientRepository = oAuth2AuthorizedClientRepository;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		var customOAuth2LoginAuthenticationFilter = new CustomOAuth2LoginAuthenticationFilter(
				this.clientRegistrationRepository,
				this.oAuth2AuthorizedClientRepository,
				super.authenticationManagerBean()
		);
		http
			.authorizeRequests()
				.anyRequest().authenticated()
				.and()
			.formLogin()
				.permitAll()
				.and()
			.authenticationProvider(customUserDetailsAuthenticationProvider)
			.oauth2Login()
				.and()
			.authenticationProvider(new CustomOidcAuthorizationCodeAuthenticationProvider())
			.addFilterBefore(customOAuth2LoginAuthenticationFilter, OAuth2LoginAuthenticationFilter.class);
				// TODO
//			.saml2Login()
//				.and()

		// TODO: redir	ect to Hello ?
	}

}
