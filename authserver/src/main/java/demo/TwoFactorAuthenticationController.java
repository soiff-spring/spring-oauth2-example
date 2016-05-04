package demo;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import model.FormData;

//This class is added per: http://stackoverflow.com/questions/30319666/two-factor-authentication-with-spring-security-oauth2
@Controller
@RequestMapping(TwoFactorAuthenticationController.PATH)
public class TwoFactorAuthenticationController {
    private static final Logger LOG = LoggerFactory.getLogger(TwoFactorAuthenticationController.class);
    public static final String PATH = "/secure/two_factor_authentication";
    public static final String ROLE_TWO_FACTOR_AUTHENTICATED = "ROLE_TWO_FACTOR_AUTHENTICATED";

    @RequestMapping(method = RequestMethod.GET)
    public String auth(HttpServletRequest request, HttpSession session/*, ....*/) {
        if (AuthenticationUtil.isAuthenticatedWithAuthority(ROLE_TWO_FACTOR_AUTHENTICATED)) {
            LOG.info("User {} already has {} authority - no need to enter code again", ROLE_TWO_FACTOR_AUTHENTICATED);
//            throw ....;
        }
        else if (session.getAttribute(CustomOAuth2RequestFactory.SAVED_AUTHORIZATION_REQUEST_SESSION_ATTRIBUTE_NAME) == null) {
//            LOG.warn("Error while entering 2FA code - attribute {} not found in session.", CustomOAuth2RequestFactory.SAVED_AUTHORIZATION_REQUEST_SESSION_ATTRIBUTE_NAME);
//          throw ....;
        }
        else{
        	return "templates/pinCode"; // Show the form to enter the 2FA secret
        }
        return "templates/pinCode";
    }

    @RequestMapping(method = RequestMethod.POST)
    public String auth(FormData formData) {
        if (formData.getPinVal()!=null) {
        	if(formData.getPinVal().equals("5309")){
        		AuthenticationUtil.addAuthority(ROLE_TWO_FACTOR_AUTHENTICATED);
        		return "forward:/oauth/authorize"; // Continue with the OAuth flow
        	};
        };

        return "templates/pinCode"; // Show the form to enter the 2FA secret again
    }
}