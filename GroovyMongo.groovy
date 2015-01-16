import com.mongodb.*
import groovy.time.*

String username = "msadow"

MongoClient mongoClient = new MongoClient( "localhost" , 27017 );

if(mongoClient){
	println("Made a connection to mongo");
	
	DB db = mongoClient.getDB("test")

	DBCollection auth_tokens = db.getCollection("authentication_tokens");

	def auth_token = auth_tokens.findOne(new BasicDBObject(["username":username]));

	if(auth_token){
		println("found auth_token ${auth_token}")

		def expiration_date = auth_token.get("expiration_date")
		println("current expiration_date ${expiration_date}")
		
		println(expiration_date.getClass().getCanonicalName())

		if(expiration_date <= new Date()){
			println("the token expired!! creating a new one");
			def new_expiration_date

			use([groovy.time.TimeCategory]){
				new_expiration_date = new Date() + 2.minutes
			}
			auth_token.put("expiration_date", new_expiration_date);
			def verify = auth_tokens.save(auth_token)
			println("updated expiration_date ${verify}")
		} else {
			println("${username} is still logged in");
		}
	} else {
		def new_expiration_date
		use([groovy.time.TimeCategory]){
			new_expiration_date = new Date() + 2.minutes
		}
		println("${new_expiration_date}")
		def verify = auth_tokens.save(new BasicDBObject(["username":username, "expiration_date" : new_expiration_date]))
		println("created a new token? ${verify}")
	}
}