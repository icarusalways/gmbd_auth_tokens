package sadow.projects.sling.authentication

import org.apache.sling.jcr.jackrabbit.server.security.AuthenticationPlugin;
import javax.jcr.Credentials;

/**
 * Necessary since groovy doesn't support anonymous innner classes
 *
 */
public class CustomAuthenticationPlugin implements AuthenticationPlugin {
	
	CustomAuthHandler authHandler

	public CustomAuthenticationPlugin(CustomAuthHandler authHandler){
		this.authHandler = authHandler
	}
	
	boolean authenticate(javax.jcr.Credentials credentials){
		return authHandler.isValid(credentials);
	}
}