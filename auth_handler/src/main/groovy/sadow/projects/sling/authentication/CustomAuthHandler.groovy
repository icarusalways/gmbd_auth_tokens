package sadow.projects.sling.authentication

//jmx annotations and support
//import com.adobe.granite.jmx.annotation.AnnotatedStandardMBean
//import javax.management.DynamicMBean
//import javax.management.NotCompliantMBeanException

//utils
import java.util.Enumeration
import java.util.Dictionary

//scr annotations
import org.apache.felix.scr.annotations.Activate
import org.apache.felix.scr.annotations.Component
import org.apache.felix.scr.annotations.Deactivate
import org.apache.felix.scr.annotations.Modified
import org.apache.felix.scr.annotations.Properties
import org.apache.felix.scr.annotations.Property
import org.apache.felix.scr.annotations.Reference
import org.apache.felix.scr.annotations.ReferenceCardinality
import org.apache.felix.scr.annotations.ReferencePolicy
import org.apache.felix.scr.annotations.Service

//apache sling reference
import org.apache.sling.jcr.api.SlingRepository

import javax.servlet.http.*

//interface for implementation and other useful classes
import org.apache.sling.auth.core.spi.*
import org.apache.sling.auth.core.*;
import org.osgi.framework.Constants;

//components
import org.osgi.service.component.ComponentContext

//loggers
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import com.mongodb.*

import javax.jcr.Credentials;
import javax.jcr.SimpleCredentials;

import org.apache.sling.api.auth.Authenticator;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.Resource;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession

/**
 * This class demonstrates the following:
 *  - Maven scr plugin annotations
 *  - Felix Web Console configuration properties using annotations
 *  - Accessing the CRX JCR
 *  - JMX methods via scr annotations
 * 
 * Note that the following are available properties on the @Component 
 * annotation:
 *  name = the PID (in the Felix Web Console Configuration tab)
 *  label = the name (in the Felix Web Console Configuration tab)
 *  description = descriptive text (in the Felix Web Console Configuration tab)
 */
@Component (metatype=true, immediate=true, label="Authentication Handler", description="Authentication Handler")

@Properties(value = [
    @Property ( name="jmx.objectname", 
                value="org.healthnow.web.authentication:type=auth_handler", 
                propertyPrivate=true ),   // To expose via JMX make sure it's private
    
    //necessary for Authentication Handler implementation
    @Property ( name="path", 
                label="Paths", 
                value="/", 
                description="One or more string values indicating the request URLs to which the AuthenticationHandler is applicable.", 
                cardinality=100),
    @Property ( name="request.cookie.name", 
                label="Name of the cookie to set and check", 
                value="login-token", 
                description="Name of the cookie to set and check"),
    @Property ( name="session.timeout", 
                label="Time in milliseconds until the cookie expires", 
                longValue=60000L, 
                description="Time in milliseconds until the cookie expires"),
    /*@Property ( name="request.url.suffix", 
                label="Request URL Suffix", 
                value="/j_security_check", 
                description="A URL suffix that when requested executes this AuthenticationHandler login mechanism"),*/
    @Property(  name = Constants.SERVICE_RANKING,
                intValue = 20,
                propertyPrivate = false)
    //optional parameter
    /*@Property ( name="authtype", 
                label="AuthType", 
                value="member", 
                description="If this property is set, the requestCredentials method of the authentication handler is only called if the sling:authRequestLogin request parameter is either not set or is set to the same value as the authtype of the handler")*/
])

/**
* SLING DOCUMENTATION
* When looking for an AuthenticationHandler the authentication handler is selected whose path is the longest match on the request URL.
* If the service is registered with Scheme and Host/Port, these must exactly match for the service to be eligible.
* If multiple AuthenticationHandler services are registered with the same length matching path, the handler with the higher service ranking is selected.
*/
@Service (value=[ AuthenticationHandler.class])
public class CustomAuthHandler extends DefaultAuthenticationFeedbackHandler implements AuthenticationHandler {

    //request url suffix
    static final String REQUEST_URL_SUFFIX = "/sad_check";
    //static final String REQUEST_URL_SUFFIX = "/j_security_check";
    //static String REQUEST_URL_SUFFIX = "/j_security_check"

    // Internal logger
    private static final Logger log = LoggerFactory.getLogger(CustomAuthHandler.class)

    // Reference to this component's context, saved during activation
    protected ComponentContext componentContext
    
    /* **** TYPES OF REFERENCES *****
     *  Cardinalities 
     *      ReferenceCardinality.MANDATORY_UNARY (at least one)
     *      ReferenceCardinality.MANDATORY_MULTIPLE (one or more)
     *      ReferenceCardinality.OPTIONAL_UNARY (if there's one we'll use it)
     *      ReferenceCardinality.OPTIONAL_MULTIPLE (use all available references)
     *  Policies
     *      ReferencePolicy.STATIC (specific to an instance)
     *      ReferencePolicy.DYNAMIC (allowed to switch instances)
     */
    
    // Reference to the SlingRepository, injected. Remove if unnecessary.
    @Reference(
            cardinality = ReferenceCardinality.MANDATORY_UNARY,
            policy = ReferencePolicy.DYNAMIC)
    private volatile SlingRepository repository

    def path = []

    def cookieName

    def sessionTimeout

    def loginModule

    def loginForm = "/sling/content/sadowlogin.html"

    def includeLoginForm = false


    public CustomAuthHandler() {}

    public String getRepositoryName(){
        String repositoryName = "Repository name unavailable."
        if(repository != null){
            repositoryName = repository.getDescriptor("jcr.repository.name")
        }
        return repositoryName
    }

    @Activate
    protected void doActivate(ComponentContext componentContext) throws Exception {
       this.componentContext = componentContext
       log.info("CustomAuthHandler - component activated")
       log.info("--------------------------------------")
       configureComponent()
       printProperties()
    }
    
    @Modified
    protected void doModified(ComponentContext componentContext) throws Exception {
        this.componentContext = componentContext
        log.info("CustomAuthHandler - component modified")
        log.info("-------------------------------------")
        configureComponent()
        printProperties()
    }
    
    @Deactivate
    protected void doDeactivate(ComponentContext componentContext) throws Exception {
        this.componentContext = componentContext
        log.info("CustomAuthHandler - component deactivated")
        log.info("----------------------------------------")
        if (loginModule != null) {
            loginModule.unregister();
            loginModule = null;
        }
    }
    
    private void printProperties() {
        final Dictionary<String, Object> properties = componentContext.getProperties()
        if(properties.size() > 0){
            StringBuffer sb = new StringBuffer()
            sb.append("\n\n----------" + CustomAuthHandler.class.getName() + "----------\n")
            for (Enumeration e = properties.keys();  e.hasMoreElements(); ) {
                Object key = e.nextElement()
                if(!key.toString().toLowerCase().contains("password")){
                    sb.append("\t" + key + " : " + properties.get(key) + "\n")
                }
            }
            sb.append("----------" + CustomAuthHandler.class.getName() + "----------\n")
            log.info(sb.toString())
        } else {
            log.info("\n-----------No Properties----------\n")
        }
    }

    private void configureComponent(){

        def properties = componentContext.getProperties()
        //this.REQUEST_URL_SUFFIX = (String)properties.get("request.url.suffix")
        this.cookieName = (String)properties.get("request.cookie.name")
        this.sessionTimeout = (long)properties.get("session.timeout")

        //ServiceRegistration
        try{
            this.loginModule = CustomAuthLoginModulePlugin.register(this, componentContext.getBundleContext());
        } catch (Throwable t){
            log.error("Cannot register CustomAuthLoginModulePlugin. This is expected if Sling LoginModulePlugin services are not supported. This is necessary for Authentication with storing passwords.");
            log.error("dump", t);
        }
    }

    /**
    *  Drops any credential and authentication details from the request and asks the client to do the same.
    */
    public void dropCredentials(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response){
        log.info("CustomAuthHandler drop credentials");
    }

    /**
    * Extracts credential data from the request if at all contained.
    */
    public AuthenticationInfo extractCredentials(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response){

        log.info("CustomAuthHandler extractCredentials")

        AuthenticationInfo info = null

        // 1. try credentials from POST'ed request parameters (a login request)
        info = this.extractRequestParameterAuthentication(request);

        // 2. try credentials from the cookie or session
        if (info == null) {
            
            //get the cookie
            def cookie = getCookie(request)

            log.info("Found cookie ${cookie}")

            if (cookie != null) {
                log.info("checking cookie store for validity of ${cookie}")
                MongoTokenStore tokenStore = new MongoTokenStore(sessionTimeout)
                if (tokenStore.isValid(cookie)) {
                    def authData = tokenStore.getAuthData(cookie)
                    def username = authData.get("username")
                    //def password = authData.get("password").toCharArray()//toArray().collect{it -> (Character)it}
                    //log.info("${password}")
                    //log.info("Found username ${username}:${password} associated with cookie")

                    //need to send back the password everytime unless we implement a LoginModulePlugin
                    //info = new AuthenticationInfo(HttpServletRequest.FORM_AUTH, username, password)
                    info = new AuthenticationInfo(HttpServletRequest.FORM_AUTH, username)

                    info.put("login-token", cookie)

                } else {
                    log.info("cookie is invalid. Attempting to clear the cookie");
                    // clear the cookie, its invalid and we should get rid of it
                    // so that the invalid cookie isn't present on the authN
                    // operation.

                    //remove cookie from datastore 
                    //this could be done on the check for isValid
                    tokenStore.clearCookie(cookie);

                    //remove the cookie from the clients browser
                    setCookie(request, response, "login-token", "", 0, null);

                    //if (this.loginAfterExpire || AuthUtil.isValidateRequest(request)) {
                        // signal the requestCredentials method a previous login
                        // failure
                        request.setAttribute(FAILURE_REASON, "Session Timeout");
                        info = AuthenticationInfo.FAIL_AUTH;
                    //}
                }
            }
        }

        log.info("return AuthenticationInfo object : ${info}")
        //AuthenticationInfo.DOING_AUTH
        //A special instance of this class which may be returned to inform the caller that a response has been sent to the client to request for credentials.
        //AuthenticationInfo.FAIL_AUTH
        //A special instance of this class which may be returned to inform the caller that credential extraction failed for some reason
        return info;
    }

    private String getCookie(HttpServletRequest request) {
        
        def cookieValue = null

        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("login-token" == cookie.getName()) {
                    String value = cookie.getValue();
                    if (value.length() > 0) {
                        cookieValue = value
                        break;
                    }
                }
            }
        }

       return cookieValue;

    }

    /**
    * Requests authentication information from the client.
    */
    public boolean requestCredentials(HttpServletRequest request, HttpServletResponse response) throws IOException {

        // 0. ignore this handler if an authentication handler is requested
        final String requestLogin = request.getParameter(REQUEST_LOGIN_PARAMETER);
        if(requestLogin != null && !HttpServletRequest.FORM_AUTH.equals(requestLogin)){
            // consider this handler is not used
            return false;
        }

        //check the referrer to see if the request is for this handler
        if (!AuthUtil.checkReferer(request, loginForm)) {
            //not for this handler, so return
            return false;
        }

        final String resource = AuthUtil.setLoginResourceAttribute(request, request.getRequestURI());

        if (includeLoginForm && (resourceResolverFactory != null)) {
            ResourceResolver resourceResolver = null;
            try {
                resourceResolver = resourceResolverFactory.getAdministrativeResourceResolver(null);
                Resource loginFormResource = resourceResolver.resolve(loginForm);
                Servlet loginFormServlet = loginFormResource.adaptTo(Servlet.class);
                if (loginFormServlet != null) {
                    try {
                        loginFormServlet.service(request, response);
                        return true;
                    } catch (ServletException e) {
                        log.error("Failed to include the form: " + loginForm, e);
                    }
                }
            } catch (LoginException e) {
                log.error("Unable to get a resource resolver to include for the login resource. Will redirect instead.");
            } finally {
                if (resourceResolver != null) {
                    resourceResolver.close();
                }
            }
        }

        HashMap<String, String> params = new HashMap<String, String>();
        params.put(Authenticator.LOGIN_RESOURCE, resource);

        // append indication of previous login failure
        if (request.getAttribute(FAILURE_REASON) != null) {
            final Object jReason = request.getAttribute(FAILURE_REASON);
            @SuppressWarnings("rawtypes")
            final String reason = (jReason instanceof Enum) ? ((Enum) jReason).name() : jReason.toString();
            params.put(FAILURE_REASON, reason);
        }

        try {
            AuthUtil.sendRedirect(request, response, loginForm, params);
        } catch (IOException e) {
            log.error("Failed to redirect to the login form " + loginForm, e);
        }

        return true;
    }

    private AuthenticationInfo extractRequestParameterAuthentication(HttpServletRequest request) {
        
        AuthenticationInfo info = null;

        // only consider login form parameters if this is a POST request
        // to the j_security_check URL
        if ("POST" == request.getMethod() && request.getRequestURI().endsWith(REQUEST_URL_SUFFIX)) {

            String user = request.getParameter("j_username");
            String pwd = request.getParameter("j_password");

            if (user != null && pwd != null) {
                info = new AuthenticationInfo(HttpServletRequest.FORM_AUTH, user, pwd.toCharArray());
                info.put(AuthConstants.AUTH_INFO_LOGIN, new Object());

                // if this request is providing form credentials, we have to
                // make sure, that the request is redirected after successful
                // authentication, otherwise the request may be processed
                // as a POST request to the j_security_check page (unless
                // the j_validate parameter is set); but only if this is not
                // a validation request
                if (!AuthUtil.isValidateRequest(request)) {
                    AuthUtil.setLoginResourceAttribute(request, request.getContextPath());
                }
            }
        }

        return info;
    }

        // ---------- AuthenticationFeedbackHandler

    /**
     * Called after an unsuccessful login attempt. This implementation makes
     * sure the authentication data is removed either by removing the cookie or
     * by remove the HTTP Session attribute.
     */
    @Override
    public void authenticationFailed(HttpServletRequest request,
            HttpServletResponse response, AuthenticationInfo authInfo) {

        log.info("Invalid credentials provided. Deleting old cookie from request.");
        /*
         * Note: This method is called if this handler provided credentials
         * which cause a login failure
         */

        // clear authentication data from Cookie or Http Session
        // delete cookie if present
        Cookie oldCookie = null;
        String oldCookieDomain = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("login-token" == cookie.getName()) {
                    // found the cookie
                    oldCookie = cookie;
                /*} else if (this.domainCookieName.equals(cookie.getName())) {
                    oldCookieDomain = cookie.getValue();
                }*/
                }
            }
        }

        // remove the old cookie from the client
        if (oldCookie != null) {
            setCookie(request, response, "login-token", "", 0, null);
            /*if (oldCookieDomain != null && oldCookieDomain.length() > 0) {
                setCookie(request, response, this.domainCookieName, "", 0, oldCookieDomain);
            }*/
        }
        //authStorage.clear(request, response);

        // signal the reason for login failure
        request.setAttribute(FAILURE_REASON, "Username and Password do not match");
    }

    /**
     * Called after successful login with the given authentication info. This
     * implementation ensures the authentication data is set in either the
     * cookie or the HTTP session with the correct security tokens.
     * <p>
     * If no authentication data already exists, it is created. Otherwise if the
     * data has expired the data is updated with a new security token and a new
     * expiry time.
     * <p>
     * If creating or updating the authentication data fails, it is actually
     * removed from the cookie or the HTTP session and future requests will not
     * be authenticated any longer.
     */
    @Override
    public boolean authenticationSucceeded(HttpServletRequest request,
            HttpServletResponse response, AuthenticationInfo authInfo) {

        log.info("Authentication Succeeded called");
        /*
         * Note: This method is called if this handler provided credentials
         * which succeeded login into the repository
         */

        // get current authentication data, may be missing after first login
        //String authData = getCookieAuthData(authInfo);
        String authData = authInfo.get("login-token");
        if(authData == null){
            MongoTokenStore mts = new MongoTokenStore(sessionTimeout)
            def cookieValue = mts.createToken(authInfo.getUser(), authInfo.getPassword())
            setCookie(request, response, "login-token", cookieValue, 5, null)
        }

        // ensure fresh authentication data (refresh if over half of the session time elapsed)
        //refreshAuthData(request, response, authInfo);

        //set the cookie
        //setCookie(request, response, "login-token", , 5, null)

        final boolean result;
        // SLING-1847: only consider a resource redirect if this is a POST request
        // to the j_security_check URL
        if ("POST" == request.getMethod() && request.getRequestURI().endsWith(REQUEST_URL_SUFFIX)) {

            if (DefaultAuthenticationFeedbackHandler.handleRedirect(request, response)) {
                // terminate request, all done in the default handler
                result = false;
            } else {
                // check whether redirect is requested by the resource parameter
                final String targetResource = AuthUtil.getLoginResource(request, null);
                if (targetResource != null) {
                    try {
                        if (response.isCommitted()) {
                            throw new IllegalStateException("Response is already committed");
                        }
                        response.resetBuffer();

                        StringBuilder b = new StringBuilder();
                        if (AuthUtil.isRedirectValid(request, targetResource)) {
                            b.append(targetResource);
                        } else if (request.getContextPath().length() == 0) {
                            b.append("/");
                        } else {
                            b.append(request.getContextPath());
                        }
                        response.sendRedirect(b.toString());
                    } catch (IOException ioe) {
                        log.error("Failed to send redirect to: " + targetResource, ioe);
                    }

                    // terminate request, all done
                    result = true;
                } else {
                    // no redirect, hence continue processing
                    result = false;
                }
            }
        } else {
            // no redirect, hence continue processing
            result = false;
        }

        // no redirect
        return result;
    }

    private void setCookie(final HttpServletRequest request, final HttpServletResponse response, 
                            final String name, final String value, final int age, final String domain) {

        final String ctxPath = request.getContextPath();
        final String cookiePath = (ctxPath == null || ctxPath.length() == 0) ? "/": ctxPath;

        /*
         * The Servlet Spec 2.5 does not allow us to set the commonly used
         * HttpOnly attribute on cookies (Servlet API 3.0 does) so we create
         * the Set-Cookie header manually. See
         * http://www.owasp.org/index.php/HttpOnly for information on what
         * the HttpOnly attribute is used for.
         */

        final StringBuilder header = new StringBuilder();

        // default setup with name, value, cookie path and HttpOnly
        header.append(name).append("=").append(value);
        header.append("; Path=").append(cookiePath);
        header.append("; HttpOnly"); // don't allow JS access

        // set the cookie domain if so configured
        if (domain != null) {
            header.append("; Domain=").append(domain);
        }

        // Only set the Max-Age attribute to remove the cookie
        /*if (age >= 0) {
            header.append("; Max-Age=").append(age);
        }*/

        // ensure the cookie is secured if this is an https request
        if (request.isSecure()) {
            header.append("; Secure");
        }

        response.addHeader("Set-Cookie", header.toString());
    }

        /**
     * Ensures the authentication data is set (if not set yet) and the expiry
     * time is prolonged (if auth data already existed).
     * Where cookie is set in response
     * <p>
     * This method is intended to be called in case authentication succeeded.
     *
     * @param request The current request
     * @param response The current response
     * @param authInfo The authentication info used to successful log in
     */
    /*private void refreshAuthData(final HttpServletRequest request,
            final HttpServletResponse response,
            final AuthenticationInfo authInfo) {

        // get current authentication data, may be missing after first login
        String authData = authInfo.get("cookie");

        log.info("found cookie ${authData}")

        // check whether we have to "store" or create the data
        final boolean refreshCookie = needsRefresh(authData,this.sessionTimeout);

        // add or refresh the stored auth hash
        if (refreshCookie) {
            long expires = System.currentTimeMillis() + this.sessionTimeout;
            try {
                authData = null;
                authData = tokenStore.encode(expires, authInfo.getUser());
            } catch (InvalidKeyException e) {
                log.error(e.getMessage(), e);
            } catch (IllegalStateException e) {
                log.error(e.getMessage(), e);
            } catch (UnsupportedEncodingException e) {
                log.error(e.getMessage(), e);
            } catch (NoSuchAlgorithmException e) {
                log.error(e.getMessage(), e);
            }

            if (authData != null) {
                authStorage.set(request, response, authData, authInfo);
            } else {
                authStorage.clear(request, response);
            }
        }
    }*/

    // ---------- LoginModulePlugin support

    private String getCookieAuthData(final Credentials credentials) {
        if (credentials instanceof SimpleCredentials) {
            Object data = ((SimpleCredentials) credentials).getAttribute("login-token");
            if (data instanceof String) {
                return (String) data;
            }
        }
        // no SimpleCredentials or no valid attribute
        return null;
    }

    public boolean hasAuthData(final Credentials credentials) {
        return getCookieAuthData(credentials) != null;
    }

    public boolean isValid(final Credentials credentials) {
        
        log.info("LoginModule Plugin checking if credentials are valid")

        String authData = getCookieAuthData(credentials);

        if (authData != null) {
            
            MongoTokenStore tokenStore = new MongoTokenStore(sessionTimeout)

            return tokenStore.isValid(authData)

        }

        // no authdata, not valid
        return false;
    }

    // END ------ LoginModulePlugin support
}