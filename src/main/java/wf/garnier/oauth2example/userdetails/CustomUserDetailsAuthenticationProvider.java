package wf.garnier.oauth2example.userdetails;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.stereotype.Component;

@Component
public class CustomUserDetailsAuthenticationProvider extends DaoAuthenticationProvider {

	public CustomUserDetailsAuthenticationProvider() {
		// These would usually be declared / wired in their own @Bean
		BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
		UserDetails user = User.withUsername("user").password(passwordEncoder.encode("password")).roles("ADMIN").build();
		InMemoryUserDetailsManager userDetailsService = new InMemoryUserDetailsManager(user);

		super.setUserDetailsService(userDetailsService);
		super.setPasswordEncoder(passwordEncoder);
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		UsernamePasswordAuthenticationToken result = (UsernamePasswordAuthenticationToken) super.authenticate(authentication);
		return new CustomUsernamePasswordAuthentication(result);
	}
}
