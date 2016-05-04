package demo;

import java.util.Map;

import javax.servlet.http.HttpSession;

import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

//This entire class is added per: http://stackoverflow.com/questions/30319666/two-factor-authentication-with-spring-security-oauth2
/**
 * If the session contains an {@link AuthorizationRequest}, this one is used and returned.
 * The {@link com.example.TwoFactorAuthenticationFilter} saved the original AuthorizationRequest. This allows
 * to redirect the user away from the /oauth/authorize endpoint during oauth authorization
 * and show him e.g. a the page where he has to enter a code for two factor authentication.
 * Redirecting him back to /oauth/authorize will use the original authorizationRequest from the session
 * and continue with the oauth authorization.
 */
public class CustomOAuth2RequestFactory extends DefaultOAuth2RequestFactory {

    public static final String SAVED_AUTHORIZATION_REQUEST_SESSION_ATTRIBUTE_NAME = "savedAuthorizationRequest";

    public CustomOAuth2RequestFactory(ClientDetailsService clientDetailsService) {
        super(clientDetailsService);
    }

    @Override
    public AuthorizationRequest createAuthorizationRequest(Map<String, String> authorizationParameters) {
        ServletRequestAttributes attr = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
        HttpSession session = attr.getRequest().getSession(false);
        if (session != null) {
            AuthorizationRequest authorizationRequest = (AuthorizationRequest) session.getAttribute(SAVED_AUTHORIZATION_REQUEST_SESSION_ATTRIBUTE_NAME);
            if (authorizationRequest != null) {
                session.removeAttribute(SAVED_AUTHORIZATION_REQUEST_SESSION_ATTRIBUTE_NAME);
                return authorizationRequest;
            }
        }

        return super.createAuthorizationRequest(authorizationParameters);
    }
}