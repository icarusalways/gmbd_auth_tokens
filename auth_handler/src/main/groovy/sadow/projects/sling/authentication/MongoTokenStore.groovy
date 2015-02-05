package sadow.projects.sling.authentication

//loggers
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import com.mongodb.*

import java.util.UUID

public class MongoTokenStore {
	
	//the amount of time before the cookie becomes invalid
	private long sessionTimeout

	// Internal logger
    private static final Logger log = LoggerFactory.getLogger(MongoTokenStore.class)

	public MongoTokenStore(long sessionTimeout){
		this.sessionTimeout = sessionTimeout
	}

	def createToken(username, profile, servers){

		def cookieValue = UUID.randomUUID().toString()

		def new_expiration_date = new Date(new Date().getTime() + sessionTimeout)
		/*def new_expiration_date
		use([groovy.time.TimeCategory]){
			new_expiration_date = new Date() + 2.minutes
		}*/

		MongoClient mongoClient = new MongoClient( "localhost" , 27017 );
		
		DB db = mongoClient.getDB("test")

		DBCollection auth_tokens = db.getCollection("authentication_tokens");

		log.info("${new_expiration_date}")

		def verify = auth_tokens.save(new BasicDBObject(["username":username, "cookie":cookieValue, "expiration_date" : new_expiration_date, "profile":profile, "servers":servers]))

		log.info("created a new token? ${verify}")

		mongoClient.close();

		return cookieValue
	}

	def getAuthData(String value){

		MongoClient mongoClient = new MongoClient( "localhost" , 27017 );
		
		DB db = mongoClient.getDB("test")

		DBCollection auth_tokens = db.getCollection("authentication_tokens");

		def auth_data = auth_tokens.findOne(new BasicDBObject(["cookie":value]));

		mongoClient.close();

		return auth_data

	}

	boolean isValid(String value){

		log.info("checking if ${value} is a valid cookie")

		boolean isValid = false;
		
		if(!value){
			log.info("cookie value is not valid (${value})")
			return isValid
		}

		MongoClient mongoClient = new MongoClient( "localhost" , 27017 );
		
		DB db = mongoClient.getDB("test")

		DBCollection auth_tokens = db.getCollection("authentication_tokens");

		def auth_token = auth_tokens.findOne(new BasicDBObject(["cookie":value]));

		if(auth_token){

			log.info("found auth_token ${auth_token}")

			def expiration_date = auth_token.get("expiration_date")

			log.info("current expiration_date ${expiration_date}")

			if(expiration_date <= new Date()){

				log.info("the token expired!! creating a new one");
				
				isValid = false;

			} else {
				log.info("${auth_token.get('username')} is still logged in with token ");
				isValid = true;
			}
		} else {
			log.info("no cookie found in mongo datastore")
		}

		mongoClient.close();

		log.info("returning isValid ${isValid}")

		return isValid;
	}

	void clearCookie(String value){

		log.info("clearing cookie ${value}")

		if(value == null || value.equals("")){
			return;
		}

		MongoClient mongoClient = new MongoClient( "localhost" , 27017 );
		
		DB db = mongoClient.getDB("test")

		DBCollection auth_tokens = db.getCollection("authentication_tokens");

		def result = auth_tokens.remove(new BasicDBObject(["cookie":value]))

		log.info("result of clear cookie operation : ${result}")

		mongoClient.close();
	}
}