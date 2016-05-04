package demo;

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

//This class is added per: http://stackoverflow.com/questions/30319666/two-factor-authentication-with-spring-security-oauth2
/**
 * Stores the oauth authorizationRequest in the session so that it can
 * later be picked by the {@link com.example.CustomOAuth2RequestFactory}
 * to continue with the authoriztion flow.
 */
public class TwoFactorAuthenticationFilter extends OncePerRequestFilter {

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private OAuth2RequestFactory oAuth2RequestFactory;
    //These next two are added as a test to avoid the compilation errors that happened when they were not defined.
    public static final String ROLE_TWO_FACTOR_AUTHENTICATED = "ROLE_TWO_FACTOR_AUTHENTICATED";
    public static final String ROLE_TWO_FACTOR_AUTHENTICATION_ENABLED = "ROLE_TWO_FACTOR_AUTHENTICATION_ENABLED";

    @Autowired
    public void setClientDetailsService(ClientDetailsService clientDetailsService) {
        oAuth2RequestFactory = new DefaultOAuth2RequestFactory(clientDetailsService);
    }

    private boolean twoFactorAuthenticationEnabled(Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream().anyMatch(
            authority -> ROLE_TWO_FACTOR_AUTHENTICATION_ENABLED.equals(authority.getAuthority())
        );
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // Check if the user hasn't done the two factor authentication.
        if (AuthenticationUtil.isAuthenticated() && !AuthenticationUtil.hasAuthority(ROLE_TWO_FACTOR_AUTHENTICATED)) {
            AuthorizationRequest authorizationRequest = oAuth2RequestFactory.createAuthorizationRequest(paramsFromRequest(request));
            /* Check if the client's authorities (authorizationRequest.getAuthorities()) or the user's ones
               require two factor authenticatoin. */
            if (twoFactorAuthenticationEnabled(authorizationRequest.getAuthorities()) ||
                    twoFactorAuthenticationEnabled(SecurityContextHolder.getContext().getAuthentication().getAuthorities())) {
                // Save the authorizationRequest in the session. This allows the CustomOAuth2RequestFactory
                // to return this saved request to the AuthenticationEndpoint after the user successfully
                // did the two factor authentication.
                request.getSession().setAttribute(CustomOAuth2RequestFactory.SAVED_AUTHORIZATION_REQUEST_SESSION_ATTRIBUTE_NAME, authorizationRequest);

                // redirect the the page where the user needs to enter the two factor authentiation code
                redirectStrategy.sendRedirect(request, response,
                        ServletUriComponentsBuilder.fromCurrentContextPath()
                            .path(TwoFactorAuthenticationController.PATH)
                            .toUriString());
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private Map<String, String> paramsFromRequest(HttpServletRequest request) {
        Map<String, String> params = new HashMap<>();
        for (Entry<String, String[]> entry : request.getParameterMap().entrySet()) {
            params.put(entry.getKey(), entry.getValue()[0]);
        }
        return params;
    }
}
