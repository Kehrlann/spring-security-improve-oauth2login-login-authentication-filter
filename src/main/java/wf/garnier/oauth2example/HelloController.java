package wf.garnier.oauth2example;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

	@GetMapping("/")
	public String hello(Authentication authentication) {
		CustomAuthentication customAuth = (CustomAuthentication) authentication;
		String sb = "";
		sb += "<body>";
		sb += "		<p>Hi, " + customAuth.getName() + "!</p>";
		sb += "		<p>You logged in using provider [" + customAuth.getProviderName() + "].</p>";
		sb += "		<p>You have " + customAuth.getNumberOfStars() + " stars.</p>";
		sb += "		<p>You are " + (customAuth.isAdmin() ? "" : "not ") + " admin.</p>";
		sb += "</body>";
		return sb;
	}

}
