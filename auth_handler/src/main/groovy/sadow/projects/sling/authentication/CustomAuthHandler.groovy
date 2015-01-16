package sadow.projects.sling.authentication

//jmx annotations and support
import com.adobe.granite.jmx.annotation.AnnotatedStandardMBean
import javax.management.DynamicMBean
import javax.management.NotCompliantMBeanException

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

//components
import org.osgi.service.component.ComponentContext

//loggers
import org.slf4j.Logger
import org.slf4j.LoggerFactory

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
                value="My property's initial value", 
                description="One or more string values indicating the request URLs to which the AuthenticationHandler is applicable.", 
                cardinality=100)
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
@Service (value=[ AuthenticationHandler.class, DynamicMBean.class ])
public class CustomAuthHandler extends AnnotatedStandardMBean implements AuthenticationHandler {

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

    /**
     * Constructor
     * 
     * @throws NotCompliantMBeanException 
     */
    public CustomAuthHandler() throws NotCompliantMBeanException {
        super(AuthenticationHandler.class)
    }

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
       printProperties()
    }
    
    @Modified
    protected void doModified(ComponentContext componentContext) throws Exception {
        this.componentContext = componentContext
        log.info("CustomAuthHandler - component modified")
        log.info("-------------------------------------")
        printProperties()
    }
    
    @Deactivate
    protected void doDeactivate(ComponentContext componentContext) throws Exception {
        this.componentContext = componentContext
        log.info("CustomAuthHandler - component deactivated")
        log.info("----------------------------------------")
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
        log.info("CustomAuthHandler extractCredentials");
        //AuthenticationInfo.DOING_AUTH
        //A special instance of this class which may be returned to inform the caller that a response has been sent to the client to request for credentials.
        //AuthenticationInfo.FAIL_AUTH
        //A special instance of this class which may be returned to inform the caller that credential extraction failed for some reason
        return null;
    }

    /**
    * Requests authentication information from the client.
    */
    public boolean requestCredentials(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response){
        log.info("CustomAuthHandler requestCredentials");
        return false;
    }
}
