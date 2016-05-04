package demo;

import java.security.KeyPair;
import java.security.Principal;

import javax.servlet.FilterRegistration;
import javax.servlet.ServletContext;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@SpringBootApplication
@Controller
@SessionAttributes("authorizationRequest")
@EnableResourceServer//annotation from Spring OAuth, which by default secures everything in an authorization server except the "/oauth/*" endpoints.
public class AuthserverApplication extends WebMvcConfigurerAdapter {

	@RequestMapping("/user")
	@ResponseBody
	public Principal user(Principal user) {
		return user;
	}

	@Override
	public void addViewControllers(ViewControllerRegistry registry) {
		registry.addViewController("/login").setViewName("login");
		registry.addViewController("/oauth/confirm_access").setViewName("authorize");
	}

	public static void main(String[] args) {
		SpringApplication.run(AuthserverApplication.class, args);
	}

	@Bean//This bean declaration method is a guess about how to replace AppConfig.TWO_FACTOR_AUTHENTICATION_BEAN from the example
	public TwoFactorAuthenticationFilter get2FAFilter(){
		return new TwoFactorAuthenticationFilter();
	}
	
	//Add the following class to set up 2FA per: http://stackoverflow.com/questions/30319666/two-factor-authentication-with-spring-security-oauth2
	@Order(200)
	public class SecurityWebApplicationInitializer extends AbstractSecurityWebApplicationInitializer {
	    @Override
	    protected void afterSpringSecurityFilterChain(ServletContext servletContext) {
	    	//The followling line is original, but was throwing an error.  Now commening it and replacing it with call to the test @bean declaration method above
	        //FilterRegistration.Dynamic twoFactorAuthenticationFilter = servletContext.addFilter("twoFactorAuthenticationFilter", new DelegatingFilterProxy(AppConfig.TWO_FACTOR_AUTHENTICATION_BEAN));
	        FilterRegistration.Dynamic twoFactorAuthenticationFilter = servletContext.addFilter("twoFactorAuthenticationFilter", new DelegatingFilterProxy(get2FAFilter()));
	        twoFactorAuthenticationFilter.addMappingForUrlPatterns(null, false, "/oauth/authorize");
	        super.afterSpringSecurityFilterChain(servletContext);
	    }
	}
	
	@Configuration
	@Order(-20)
	protected static class LoginConfig extends WebSecurityConfigurerAdapter {

		@Autowired
		private AuthenticationManager authenticationManager;
		
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin().loginPage("/login").permitAll()
			.and()
				.requestMatchers().antMatchers("/login", "/oauth/authorize", "/oauth/confirm_access")
			.and()
				.authorizeRequests().anyRequest().authenticated();
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.parentAuthenticationManager(authenticationManager);
		}
		
	}

	//Add the following class to connect the custom UserDetailsService
	@Order(Ordered.HIGHEST_PRECEDENCE)
	@Configuration
	protected static class WebSecurityConfiguration extends GlobalAuthenticationConfigurerAdapter {

		@Autowired
		Users users;
		
		@Override
		public void init(AuthenticationManagerBuilder auth) throws Exception {
			auth.userDetailsService(users);
		}

	}
	
	@Configuration
	@EnableAuthorizationServer
	protected static class OAuth2AuthorizationConfig extends AuthorizationServerConfigurerAdapter {

		@Autowired
		private AuthenticationManager authenticationManager;
		
		@Autowired//ADDED AS A TEST TO TRY TO HOOK UP THE CUSTOM REQUEST FACTORY
		private ClientDetailsService clientDetailsService;
		
		@Autowired//Added per: http://stackoverflow.com/questions/30319666/two-factor-authentication-with-spring-security-oauth2
		private CustomOAuth2RequestFactory customOAuth2RequestFactory;

		//THIS NEXT BEAN IS A TEST AND SHOULD BE MOVED TO WHERE THE CLIENT DETAILS ARE	
		@Bean CustomOAuth2RequestFactory customOAuth2RequestFactory(){
			return new CustomOAuth2RequestFactory(clientDetailsService);
		}
		
		@Bean
		public JwtAccessTokenConverter jwtAccessTokenConverter() {
			JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
			KeyPair keyPair = new KeyStoreKeyFactory(
						new ClassPathResource("keystore.jks"), "foobar".toCharArray()
					)
					.getKeyPair("test");
			converter.setKeyPair(keyPair);
			return converter;
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			clients.inMemory()
					.withClient("acme")//API: http://docs.spring.io/spring-security/oauth/apidocs/org/springframework/security/oauth2/config/annotation/builders/ClientDetailsServiceBuilder.ClientBuilder.html
						.secret("acmesecret")
						.authorizedGrantTypes("authorization_code", "refresh_token", "password")
						.autoApprove(true)
					.scopes("openid");
		}

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints//API: http://docs.spring.io/spring-security/oauth/apidocs/org/springframework/security/oauth2/config/annotation/web/configurers/AuthorizationServerEndpointsConfigurer.html
				.authenticationManager(authenticationManager)
				.accessTokenConverter(jwtAccessTokenConverter())
				.requestFactory(customOAuth2RequestFactory);//Added per: http://stackoverflow.com/questions/30319666/two-factor-authentication-with-spring-security-oauth2
		}

		@Override
		public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
			oauthServer//API: http://docs.spring.io/spring-security/oauth/apidocs/org/springframework/security/oauth2/config/annotation/web/configurers/AuthorizationServerSecurityConfigurer.html
				.tokenKeyAccess("permitAll()")
				.checkTokenAccess("isAuthenticated()");
		}

	}
}
