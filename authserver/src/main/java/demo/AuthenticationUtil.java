package demo;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.util.WebUtils;

//This entire class is added from: https://gist.github.com/ractive/f9b792edcf589ef43b8c644635c4ac86
//Per the example at: http://stackoverflow.com/questions/30319666/two-factor-authentication-with-spring-security-oauth2
public class AuthenticationUtil {
	private AuthenticationUtil() {} // private c'tor for utility class

	private static final AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();

	/**
	 * @return {@code true} if the user is authenticated non-anonymously
	 */
	public static boolean isAuthenticated(Authentication authentication) {
		return authentication != null &&
			authentication.isAuthenticated() &&
			!authenticationTrustResolver.isAnonymous(authentication);
	}

	/**
	 * @return {@code true} if the user is authenticated non-anonymously
	 */
	public static boolean isAuthenticated() {
		return isAuthenticated(SecurityContextHolder.getContext().getAuthentication());
	}

	/**
	 * Checks if the user has the given authority granted
	 *
	 * @param authority granted authority to check for
	 * @return {@code true} if the user has the given authority granted
	 */
	public static boolean hasAuthority(String authority) {
		return Optional.ofNullable(SecurityContextHolder.getContext().getAuthentication())
			.map(authentication -> hasAuthority(authentication, authority))
			.orElse(false);
	}

	/**
	 * Checks if the given authentication has the given authority granted
	 *
	 * @param authentication authentication to check for the authority
	 * @param authority granted authority to check for
	 * @return {@code true} if the given authentication has the given authority granted
	 */
	public static boolean hasAuthority(Authentication authentication, final String authority) {
		return authentication.getAuthorities().stream().anyMatch(
			grantedAuthority -> grantedAuthority.getAuthority().equals(authority)
		);
	}

	/**
	 * Checks if the user is authenticated by calling {@link #isAuthenticated} and if the granted authorities contain the given authority
	 * by calling {@link #hasAuthority}.
	 *
	 * @param authority
	 * @return {@code true} if the user is authenticated and has the given authority granted
	 */
	public static boolean isAuthenticatedWithAuthority(String authority) {
		if (!isAuthenticated()) {
			return false;
		}
		return hasAuthority(authority);
	}
	
		/**
	 * Creates a new {@link UsernamePasswordAuthenticationToken} with the current
	 * principal, credentials and details and with the current authorities plus the given one.
	 * This newly created authentication is set as the current one
	 * in the {@link SecurityContext}.
	 *
	 * @param authority
	 */
	public static void addAuthority(String authority) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (!isAuthenticated(authentication)) {
			return;
		}

		List<GrantedAuthority> authorities = new ArrayList<>(authentication.getAuthorities());
		authorities.add(new SimpleGrantedAuthority(authority));
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(authentication.getPrincipal(), authentication.getCredentials(), authorities);
		token.setDetails(authentication.getDetails());
		SecurityContextHolder.getContext().setAuthentication(token);
	}
}