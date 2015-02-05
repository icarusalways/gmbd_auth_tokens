package sadow.projects.sling.authentication

import org.apache.sling.jcr.jackrabbit.server.security.AuthenticationPlugin;
import javax.jcr.Credentials;

//loggers
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * Necessary since groovy doesn't support anonymous innner classes
 *
 */
public class CustomAuthenticationPlugin implements AuthenticationPlugin {

	// Internal logger
    private static final Logger log = LoggerFactory.getLogger(CustomAuthenticationPlugin.class)
	
	CustomAuthHandler authHandler

	public CustomAuthenticationPlugin(CustomAuthHandler authHandler){
		this.authHandler = authHandler
	}
	
	boolean authenticate(javax.jcr.Credentials credentials){
		log.info("calling CustomAuthenticationPlugin authenticate")
		return authHandler.isValid(credentials);
	}
}