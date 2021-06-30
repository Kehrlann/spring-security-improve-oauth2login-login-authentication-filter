package wf.garnier.oauth2example;

import org.springframework.security.core.Authentication;

public interface CustomAuthentication extends Authentication {

	String getProviderName();

	int getNumberOfStars();

	boolean isAdmin();

	String getName();
}
