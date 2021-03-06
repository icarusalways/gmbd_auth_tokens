package sadow.projects.sling.authentication

import java.security.Principal;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;

import javax.jcr.Credentials;
import javax.jcr.SimpleCredentials;
import javax.jcr.Session;
import javax.security.auth.callback.CallbackHandler;
import org.apache.sling.jcr.jackrabbit.server.security.AuthenticationPlugin;
import org.apache.sling.jcr.jackrabbit.server.security.LoginModulePlugin;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceRegistration;

//loggers
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * The <code>FormLoginModulePlugin</code> is a LoginModulePlugin which handles
 * <code>SimpleCredentials</code> attributed with the special authentication
 * data provided by the {@link FormAuthenticationHandler}.
 * <p>
 * This class is instantiated by the {@link FormAuthenticationHandler} calling
 * the {@link #register(FormAuthenticationHandler, BundleContext)} method. If
 * the OSGi framework does not provide the <code>LoginModulePlugin</code>
 * interface (such as when the Sling Jackrabbit Server bundle is not used to
 * provide the JCR Repository), loading this class fails, which is caught by the
 * {@link FormAuthenticationHandler}.
 */
final class CustomAuthLoginModulePlugin implements LoginModulePlugin {

    /**
     * The {@link FormAuthenticationHandler} used to validate the credentials
     * and its contents.
     */
    private final CustomAuthHandler authHandler;

    // Internal logger
    private static final Logger log = LoggerFactory.getLogger(CustomAuthLoginModulePlugin.class)

    /**
     * Creates an instance of this class and registers it as a
     * <code>LoginModulePlugin</code> service to handle login requests with
     * <code>SimpleCredentials</code> provided by the
     * {@link FormAuthenticationHandler}.
     *
     * @param authHandler The {@link FormAuthenticationHandler} providing
     *            support to validate the credentials
     * @param bundleContext The <code>BundleContext</code> to register the
     *            service
     * @return The <code>ServiceRegistration</code> of the registered service for
     *         the {@link FormAuthenticationHandler} to unregister the service
     *         on shutdown.
     */
    static ServiceRegistration register(
            final CustomAuthHandler authHandler,
            final BundleContext bundleContext) {
        CustomAuthLoginModulePlugin plugin = new CustomAuthLoginModulePlugin(authHandler);

        Hashtable<String, Object> properties = new Hashtable<String, Object>();
        properties.put(Constants.SERVICE_DESCRIPTION,
            "LoginModulePlugin Support for CustomAuthHandler");

        /*log.info("${bundleContext}")
        log.info("${bundleContext.getBundle()}")
        log.info("${bundleContext.getBundle().getHeaders()}")
        log.info("${Constants.BUNDLE_VENDOR}")
        properties.put(Constants.SERVICE_VENDOR,
            bundleContext.getBundle().getHeaders().get(Constants.BUNDLE_VENDOR));*/

        return bundleContext.registerService(LoginModulePlugin.class.getName(),
            plugin, properties);
    }

    /**
     * Private constructor called from
     * {@link #register(FormAuthenticationHandler, BundleContext)} to create an
     * instance of this class.
     *
     * @param authHandler The {@link FormAuthenticationHandler} used to validate
     *            the credentials attribute
     */
    private CustomAuthLoginModulePlugin(final CustomAuthHandler authHandler) {
        this.authHandler = authHandler;
    }

    /**
     * Returns <code>true</code> indicating support if the credentials is a
     * <code>SimplerCredentials</code> object and has an authentication data
     * attribute.
     *
     * This method is extremely important to handle errors properly and return 
     * true or false. Else this login module will handle all requests including
     * those to the admin console. It's very hard to remove the module once it is 
     * in place in such a state.
     *
     * @see CookieAuthenticationHandler#hasAuthData(Credentials)
     */
    public boolean canHandle(Credentials credentials) {
        
        boolean retval = false;
        log.info("Checking if this login module can handle the credentials")
        try{
            retval = authHandler.hasAuthData(credentials);
        } catch (Exception e ){
            log.error("Exception in LoginModule canHandle method ",e)
            retval = false   
        }
        log.info("canHandle creds ${retval}")

        //returning false will let the default LoginModule run and log the user into the jcr
        return retval;
    }

    /**
     * This implementation does nothing.
     */
    @SuppressWarnings("unchecked")
    public void doInit(CallbackHandler callbackHandler, Session session, Map options) {}

    /**
     * Returns <code>null</code> to have the <code>DefaultLoginModule</code>
     * provide a principal based on an existing user defined in the repository.
     */
    public Principal getPrincipal(final Credentials credentials) {
        //create user if they don't exist
        log.info("get principal")

        try{
            authHandler.checkUserExists(credentials)
        } catch (Exception e){
            log.error("something happend when checking if the profile exists ", e)
        }

        return null;
    }

    /**
     * This implementation does nothing.
     */
    @SuppressWarnings("unchecked")
    public void addPrincipals(@SuppressWarnings("unused") Set principals) {}

    /**
     * Returns an <code>AuthenticationPlugin</code> which authenticates the
     * credentials if the contain authentication data and the authentication
     * data can is valid.
     *
     * @see CookieAuthenticationHandler#isValid(Credentials)
     */
    public AuthenticationPlugin getAuthentication(Principal principal, Credentials creds) {
        log.info("LoginModule getAuthentication called. Returning new instance of CustomAuthenticationPlugin")
        return new CustomAuthenticationPlugin(authHandler);
    }

    /**
     * Returns <code>LoginModulePlugin.IMPERSONATION_DEFAULT</code> to indicate
     * that this plugin does not itself handle impersonation requests.
     */
    public int impersonate(Principal principal, Credentials credentials) {
        return LoginModulePlugin.IMPERSONATION_DEFAULT;
    }
}