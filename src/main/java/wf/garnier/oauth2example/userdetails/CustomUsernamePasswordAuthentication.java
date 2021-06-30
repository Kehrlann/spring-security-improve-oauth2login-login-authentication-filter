package wf.garnier.oauth2example.userdetails;

import java.util.Random;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import wf.garnier.oauth2example.CustomAuthentication;

public class CustomUsernamePasswordAuthentication extends UsernamePasswordAuthenticationToken implements CustomAuthentication {

	private final int numberOfStars;
	private final boolean admin;

	public CustomUsernamePasswordAuthentication(UsernamePasswordAuthenticationToken baseAuthentication) {
		super(baseAuthentication.getPrincipal(), baseAuthentication.getCredentials(), baseAuthentication.getAuthorities());

		this.numberOfStars = 1 + new Random().nextInt(5);
		this.admin = baseAuthentication.getAuthorities()
				.stream()
				.map(a -> (SimpleGrantedAuthority) a)
				.map(SimpleGrantedAuthority::getAuthority)
				.anyMatch("ROLE_ADMIN"::equals);
	}

	@Override
	public String getProviderName() {
		return "internal/user-details-service";
	}

	@Override
	public int getNumberOfStars() {
		return this.numberOfStars;
	}

	@Override
	public boolean isAdmin() {
		return this.admin;
	}
}
