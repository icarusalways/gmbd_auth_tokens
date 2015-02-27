package sadow.projects.sling.authentication

/**
* Interface meant to store and authentication data
* from another system.
* Designed so that it can be implemented by multiple OSGi services
*/
public interface TokenStore {

	public String createToken();

	public boolean isValid(String value);

	/**
	*
	*/
	public void updateToken(Map<String,String> updates);

	public User getDataWithToken(String value);

	public boolean clearToken(String value);
}