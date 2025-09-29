package com.forest.usermanagement.config;

import java.util.ArrayList;
import java.util.List;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ServerWebExchange;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.forest.messageconfig.MESSAGE;



/**
 * @author kaushal karkar
 *
 *
 */
@Service
public class KeycloakAPI {
	
	@Value("${api.redirect.token.url}")
	private String tokenEndpoint;
	
	@Value("${api.redirect.client.id}")
	private String clienIdString;
	
	@Value("${api.redirect.client.secret}")
	private String clientSecretString;
	
	@Value("${api.redirect.user.create.url}")
	private String userCreateUrl;
	
	@Value("${api.redirect.user.get.url}")
	private String getUserUrl;
	
	@Value("${api.keycloak.realms}")
	private String realms;
	
	@Value("${api.keycloak.base.url}")
	private String baseUrl;

	
	
	 public String keyCloakTokenAccess() {
		    // Set the token endpoint URL
	        String urlEndpoint = tokenEndpoint;
	        // Set the client credentials
	        String clientId = clienIdString;
	        String clientSecret = clientSecretString;
	        RestTemplate restTemplate = new RestTemplate();
	        // Set the request headers
	        HttpHeaders headers = new HttpHeaders();
	        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
	        // Set the request body parameters
	        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
	        requestBody.add("grant_type", "client_credentials");
	        requestBody.add("client_id", clientId);
	        requestBody.add("client_secret", clientSecret);
	        // Create the HTTP request entity
	        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(requestBody, headers);
	        // Make the HTTP POST request
	        ResponseEntity<String> responseEntity = restTemplate.exchange(urlEndpoint, HttpMethod.POST, requestEntity, String.class);
	        // Get the response body and status code
	        String responseBody = responseEntity.getBody();	        
	        return responseBody;
	 }
	 
	 
	 public String keyCloakUserCreate(String accessToken, String userName, String mobileNumber, String emailAddress, String password) {
		        String userCreateAPI = userCreateUrl;
		        RestTemplate restTemplate = new RestTemplate();
		     // Set the request headers
		        HttpHeaders headers = new HttpHeaders();
		        headers.setContentType(MediaType.APPLICATION_JSON);
		        headers.set("Authorization", "Bearer " + accessToken);		        
		        List<CredentialsDTO> credentialList = new ArrayList<>();		        
		        CredentialsDTO credentialsData = new CredentialsDTO();
		        credentialsData.setType("password");
		        credentialsData.setValue(password != null ? password : "Admin@123");
		        credentialsData.setTemporary(false);
		        credentialList.add(credentialsData);		        
		        UserMasterDTO userMaster = new UserMasterDTO();
		        userMaster.setEnabled(true);
		        userMaster.setUsername(userName);
		        userMaster.setCredentials(credentialList);
		        if(emailAddress != null) {
		        	userMaster.setEmail(emailAddress);
		        }		        
		        if(mobileNumber != null) {
		        	AttributesDTO attributes = new AttributesDTO();
		        	attributes.setMobileNumber(mobileNumber);
		        	userMaster.setAttributes(attributes);
		        }  		        
		        // Convert the UserMaster object to JSON
		        ObjectMapper objectMapper = new ObjectMapper();
		        String requestBody;
		        try {
		            requestBody = objectMapper.writeValueAsString(userMaster);
		        } catch (Exception e) {
		            System.err.println("Error converting UserMaster to JSON: " + e.getMessage());
		            return null;
		        }
		        // Create the HTTP entity
		        HttpEntity<String> requestEntity = new HttpEntity<>(requestBody, headers);
		     // Make the HTTP POST request
		        ResponseEntity<String> responseEntity = restTemplate.exchange(userCreateAPI, HttpMethod.POST, requestEntity, String.class);
		        String responseBody = getKeyCloakUser(accessToken, userName);
		        return responseBody;
		 }
	 
	 private String getKeyCloakUser(String accessToken, String userName){
	        try {
	        	String keycloakBaseUrl = getUserUrl;
		        HttpHeaders headers = new HttpHeaders();
		        headers.set("Authorization", "Bearer " + accessToken);
		        RestTemplate restTemplate = new RestTemplate();
		        String userUrl = keycloakBaseUrl + "/users?username=" + userName;		        
		        HttpEntity<String> requestEntity = new HttpEntity<>(headers);		       
		        ResponseEntity<String> responseEntity = restTemplate.exchange(userUrl, HttpMethod.GET, requestEntity, String.class);
		        String responseBody = responseEntity.getBody();	        	
	            ObjectMapper objectMapper = new ObjectMapper();
	            JsonNode jsonNode = objectMapper.readTree(responseBody);
	            String userId = null;	            
	            if (jsonNode.isArray()) {
	                JsonNode firstElement = jsonNode.get(0);
	                userId = firstElement.get("id").asText();
	                return userId;	                
	            } else {
	            	return null;
	            }
	        } catch (Exception e) {
	            return null;
	        }
	    }
	 
	 public String keyCloakUserUpdate(String accessToken, String email, String mobileNumber, String userId,String userName) {
	        String userCreateAPI = userCreateUrl + "/" + userId;
	        RestTemplate restTemplate = new RestTemplate();
	     // Set the request headers
	        HttpHeaders headers = new HttpHeaders();
	        headers.setContentType(MediaType.APPLICATION_JSON);
	        headers.set("Authorization", "Bearer " + accessToken);   
	        UserMasterDTO userMaster = new UserMasterDTO();
	        if(email != null) {
	        	userMaster.setEmail(email);
	        	userMaster.setUsername(userName);
	        }
	        if(mobileNumber != null) {
	        	AttributesDTO attributes = new AttributesDTO();
	        	attributes.setMobileNumber(mobileNumber);
	        	userMaster.setAttributes(attributes);
	        }
//	        userMaster.setEnabled(enabled); 
	        // Convert the UserMaster object to JSON
	        ObjectMapper objectMapper = new ObjectMapper();
	        String requestBody;	        
	        try {
	            requestBody = objectMapper.writeValueAsString(userMaster);
	        } catch (Exception e) {	           
	            e.printStackTrace();
	            return null;
	        }        
	        String responseBody = null;	        
	        // Create the HTTP entity
	        HttpEntity<String> requestEntity = new HttpEntity<>(requestBody, headers);
	     // Make the HTTP POST request
	        ResponseEntity<String> responseEntity = restTemplate.exchange(userCreateAPI, HttpMethod.PUT, requestEntity, String.class);	        
	        if (responseEntity.getStatusCode() == HttpStatus.OK) {
	            // Success
	            responseBody = responseEntity.getBody();
	        } else if(responseEntity.getStatusCode() == HttpStatus.CONFLICT) {
	        	responseBody = responseEntity.getBody();
	        	throw new HttpClientErrorException(HttpStatus.CONFLICT);	        	
	        }	        
	        return responseBody;
	 }
	 
	 public String keycloakUserUpdateStatus(String accessToken, boolean enabled, String userId) {
	        String userCreateAPI = userCreateUrl + "/" + userId;
	        RestTemplate restTemplate = new RestTemplate();
	     // Set the request headers
	        HttpHeaders headers = new HttpHeaders();
	        headers.setContentType(MediaType.APPLICATION_JSON);
	        headers.set("Authorization", "Bearer " + accessToken);
	        UserMasterDTO userMaster = new UserMasterDTO();
	        userMaster.setEnabled(enabled);
	        // Convert the UserMaster object to JSON
	        ObjectMapper objectMapper = new ObjectMapper();
	        String requestBody;
	        try {
	            requestBody = objectMapper.writeValueAsString(userMaster);
	        } catch (Exception e) {
	            return null;
	        }
	        // Create the HTTP entity
	        HttpEntity<String> requestEntity = new HttpEntity<>(requestBody, headers);
	     // Make the HTTP POST request
	        ResponseEntity<String> responseEntity = restTemplate.exchange(userCreateAPI, HttpMethod.PUT, requestEntity, String.class);
	        return responseEntity.getBody();
	 }
	 
	 public String keycloakUserDelete(String accessToken, String userId) {
	        String userDeleteAPI = userCreateUrl + "/" + userId;
	        RestTemplate restTemplate = new RestTemplate();
	     // Set the request headers
	        HttpHeaders headers = new HttpHeaders();
	        headers.setContentType(MediaType.APPLICATION_JSON);
	        headers.set("Authorization", "Bearer " + accessToken);          
	        // Create the HTTP entity
	        HttpEntity<Void> requestEntity = new HttpEntity<>(headers);
	     // Make the HTTP POST request
	        ResponseEntity<String> responseEntity = restTemplate.exchange(userDeleteAPI, HttpMethod.DELETE, requestEntity, String.class);	        
	        return responseEntity.getBody();
	 }
	 
	 public String keyCloakLogin(String userName, String userPassword) {
	        String urlEndpoint = baseUrl + "/realms/" + realms + "/protocol/openid-connect/token";
	        String clientId = clienIdString;
	        String clientSecret = clientSecretString;
	        RestTemplate restTemplate = new RestTemplate();
	        // Set the request headers
	        HttpHeaders headers = new HttpHeaders();
	        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
	        // Set the request body parameters
	        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
	        requestBody.add("grant_type", "password");
	        requestBody.add("client_id", clientId);
	        requestBody.add("client_secret", clientSecret);
	        requestBody.add("username", userName);
	        requestBody.add("password", userPassword);
	        // Create the HTTP request entity
	        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(requestBody, headers);
	        // Make the HTTP POST request
	        ResponseEntity<String> responseEntity = restTemplate.exchange(urlEndpoint, HttpMethod.POST, requestEntity, String.class);
	        String responseBody = null;   
	        if (responseEntity.getStatusCode() == HttpStatus.OK) {
	            // Success
	            responseBody = responseEntity.getBody();
	        } else if(responseEntity.getStatusCode() == HttpStatus.UNAUTHORIZED) {
	        	throw new HttpClientErrorException(HttpStatus.UNAUTHORIZED);
	        	
	        } else if(responseEntity.getStatusCode() == HttpStatus.BAD_REQUEST) {
	        	
	        	if (responseEntity.getBody().contains("Account disabled")) {
	                throw new CustomAccountDisabledException("User account is disabled");
	            } else {
	            	throw new HttpClientErrorException(HttpStatus.BAD_REQUEST);
	            }
	        }
	        else {
	        	responseBody = responseEntity.getBody();
	        } 
	        return responseBody;
	 }

	 
	 class CustomAccountDisabledException extends RuntimeException {
		private static final long serialVersionUID = 1L;
			public CustomAccountDisabledException(String message) {
		        super(message);
		    }
		}
	 
	 public boolean isTokenValid(String accessToken) {
		 boolean isValid = false;
		 try {
			 String userUrl = baseUrl + "/realms/" + realms + "/protocol/openid-connect/userinfo";
			 HttpHeaders headers = new HttpHeaders();
		        headers.set("Authorization", "Bearer " + accessToken);
		        RestTemplate restTemplate = new RestTemplate();
		        HttpEntity<String> requestEntity = new HttpEntity<>(headers);
		        ResponseEntity<String> responseEntity = restTemplate.exchange(userUrl, HttpMethod.GET, requestEntity, String.class);		        
		        if (responseEntity.getStatusCode() == HttpStatus.OK) {
		            // Success
		            isValid = true;
		        } else {
		        	isValid = false;
		        }			 
		 } catch (Exception e) {			
			isValid = false;
		}		 
		 return isValid;
	 }
	 
	 public String getUserId(String accessToken) {
		 String userId = null;
		 try {
			 String userUrl = baseUrl + "/realms/" + realms + "/protocol/openid-connect/userinfo";
			 HttpHeaders headers = new HttpHeaders();
		        headers.set("Authorization", "Bearer " + accessToken);
		        RestTemplate restTemplate = new RestTemplate();
		        HttpEntity<String> requestEntity = new HttpEntity<>(headers);
		        ResponseEntity<String> responseEntity = restTemplate.exchange(userUrl, HttpMethod.GET, requestEntity, String.class);		        
		        if (responseEntity.getStatusCode() == HttpStatus.OK) {
		            // Success
		        	JSONObject jsonResponseObject = new JSONObject(responseEntity.getBody());
		        	userId = jsonResponseObject.getString("sub");
		        } 
		 } catch (Exception e) {
			userId = null;
		} 
		 return userId;
	 }
	 
	 
	 public String keyCloakLogout(String refreshToken, ServerWebExchange httpServletRequest) {
		    String urlEndpoint = baseUrl + "/realms/" + realms + "/protocol/openid-connect/logout";
	        String clientId = clienIdString;
	        String clientSecret = clientSecretString;
	        RestTemplate restTemplate = new RestTemplate();	        
	        String authorizationHeader = httpServletRequest.getRequest().getHeaders().getFirst("Authorization");
	        String token = null;
	        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
	            token = authorizationHeader.substring(7);
	        } else {
	        	throw new HttpClientErrorException(HttpStatus.UNAUTHORIZED);
	        }
//	        // Set the request headers
	        HttpHeaders headers = new HttpHeaders();
	        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
	        headers.set("Authorization", "Bearer " + token);
//	        // Set the request body parameters
	        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
	        requestBody.add("client_id", clientId);
	        requestBody.add("client_secret", clientSecret);
	        requestBody.add("refresh_token", refreshToken);	      
//	        // Create the HTTP request entity
	        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(requestBody, headers);
	        String response = null;
//	        // Make the HTTP POST request
	        ResponseEntity<String> responseEntity = restTemplate.exchange(urlEndpoint, HttpMethod.POST, requestEntity, String.class);
	        if (responseEntity.getStatusCode() == HttpStatus.NO_CONTENT) {
	        	JSONObject res = new JSONObject();
	        	 res.put("responseCode", HttpStatus.ACCEPTED);
	             res.put("responseMessage", MESSAGE.SUCCESS);
//	        	throw new HttpClientErrorException(HttpStatus.OK);
	            response = res.toString();
	        } else {
	        	throw new HttpClientErrorException(HttpStatus.INTERNAL_SERVER_ERROR);
	        }	        
	        return response;
	 }
	 
	 
	 public String keyCloakUserResetPsw( String usetId, String userPsw) {
	        String userCreateAPI = baseUrl + "/admin/realms/" + realms + "/users/" + usetId + "/reset-password";
	        String token = keyCloakTokenAccess();
	        JSONObject jsonResponseObject = new JSONObject(token);
	        String accessToken = jsonResponseObject.getString("access_token");        
	        RestTemplate restTemplate = new RestTemplate();
	     // Set the request headers
	        HttpHeaders headers = new HttpHeaders();
	        headers.setContentType(MediaType.APPLICATION_JSON);
	        headers.set("Authorization", "Bearer " + accessToken);	        
	        List<CredentialsDTO> credentialList = new ArrayList<>();	        
	        CredentialsDTO credentialsData = new CredentialsDTO();
	        credentialsData.setType("password");
	        credentialsData.setValue(userPsw);
	        credentialsData.setTemporary(false);
	        credentialList.add(credentialsData);	      	        
	        // Convert the UserMaster object to JSON
	        ObjectMapper objectMapper = new ObjectMapper();
	        String requestBody;	        
	        try {
	            requestBody = objectMapper.writeValueAsString(credentialsData);
	        } catch (Exception e) {
	            return null;
	        }
	        // Create the HTTP entity
	        HttpEntity<String> requestEntity = new HttpEntity<>(requestBody, headers);
	     // Make the HTTP POST request
	        ResponseEntity<String> responseEntity = restTemplate.exchange(userCreateAPI, HttpMethod.PUT, requestEntity, String.class);
	        String response = null;
	        if (responseEntity.getStatusCode() == HttpStatus.NO_CONTENT) {
	        	JSONObject res = new JSONObject();
	        	 res.put("responseCode", HttpStatus.ACCEPTED);
	             res.put("responseMessage", MESSAGE.SUCCESS);
	            response = res.toString();
	        } else {
	        	throw new HttpClientErrorException(HttpStatus.INTERNAL_SERVER_ERROR);
	        }	        
	        return response;
	 }
	 

	 public boolean confirmPassword(String userName, String password) {
		 boolean isMatched = false;
		 try {	 
				String response = keyCloakLogin(userName,password);				
				JSONObject userDetails = new JSONObject(response);
				String accessToken = userDetails.getString("access_token");				
				if(accessToken != null) {
					isMatched = true;
				} else {
					isMatched = false;
				}				
				return isMatched;
			} catch (HttpClientErrorException e) {
		        if (e.getStatusCode() == HttpStatus.UNAUTHORIZED) {
		        	isMatched = false;
		        } else {		            
		            isMatched = false;
		        }
		        return isMatched;
		    } catch (Exception e) {
		        isMatched = false;
		        return isMatched;
		    }
	 }
		
	 
	 class UserMasterDTO {
			Boolean enabled;
			String username;
			String email;
			List<CredentialsDTO> credentials;	
			AttributesDTO attributes;
			
			public Boolean getEnabled() {
				return enabled;
			}
			public void setEnabled(Boolean enabled) {
				this.enabled = enabled;
			}
			public String getUsername() {
				return username;
			}
			public void setUsername(String username) {
				this.username = username;
			}
			
			public String getEmail() {
				return email;
			}
			public void setEmail(String email) {
				this.email = email;
			}
			public List<CredentialsDTO> getCredentials() {
				return credentials;
			}
			public void setCredentials(List<CredentialsDTO> credentials) {
				this.credentials = credentials;
			}
			public AttributesDTO getAttributes() {
				return attributes;
			}
			public void setAttributes(AttributesDTO attributes) {
				this.attributes = attributes;
			}
			
			

		}
	 
	 class CredentialsDTO{
		 String type;
		 String value;
		 Boolean temporary;
		 
		public String getType() {
			return type;
		}
		public void setType(String type) {
			this.type = type;
		}
		
		public String getValue() {
			return value;
		}
		public void setValue(String value) {
			this.value = value;
		}
		public Boolean getTemporary() {
			return temporary;
		}
		public void setTemporary(Boolean temporary) {
			this.temporary = temporary;
		}
		 
		 
	 }
	 
	 class AttributesDTO{
		 String mobileNumber;

		public String getMobileNumber() {
			return mobileNumber;
		}
		public void setMobileNumber(String mobileNumber) {
			this.mobileNumber = mobileNumber;
		}
		 
		 
	 }

	
	public String getUserId(ServerWebExchange request) {
		String requestTokenHeader = request.getRequest().getHeaders().getFirst("Authorization");
		String userId = null;
		if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
			String jwtToken = requestTokenHeader.substring(7);
			try {
				userId = getUserIdFromToken(jwtToken);
			} catch (Exception e) {
				
				return userId;
			}
		}
		return userId;
	}

	public String getUserIdFromToken(String accessToken) {
		String userId = null;
		try {
			String userUrl = baseUrl + "/realms/" + realms + "/protocol/openid-connect/userinfo";
			HttpHeaders headers = new HttpHeaders();
			headers.set("Authorization", "Bearer " + accessToken);
			RestTemplate restTemplate = new RestTemplate();
			HttpEntity<String> requestEntity = new HttpEntity<>(headers);
			ResponseEntity<String> responseEntity = restTemplate.exchange(userUrl, HttpMethod.GET, requestEntity,String.class);
			if (responseEntity.getStatusCode() == HttpStatus.OK) {
				// Success
				JSONObject jsonResponseObject = new JSONObject(responseEntity.getBody());
				userId = jsonResponseObject.getString("sub");
			}
		} catch (Exception e) {
			userId = null;
		}
		return userId;
	}
	
	
	public String keyCloakLogoutOtherDevice(String refreshToken, String token) {  
        String urlEndpoint = baseUrl + "/realms/" + realms + "/protocol/openid-connect/logout";
        String clientId = clienIdString;
        String clientSecret = clientSecretString;
        RestTemplate restTemplate = new RestTemplate();
        
//        String authorizationHeader = httpServletRequest.getHeader("Authorization");
//        String token = null;
//        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
//            token = authorizationHeader.substring(7);
//        } else {
//        	throw new HttpClientErrorException(HttpStatus.UNAUTHORIZED);
//        }

//        // Set the request headers
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set("Authorization", "Bearer " + token);
//        // Set the request body parameters
        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("client_id", clientId);
        requestBody.add("client_secret", clientSecret);
        requestBody.add("refresh_token", refreshToken);
//        // Create the HTTP request entity
        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(requestBody, headers);
        String response = null;
//        // Make the HTTP POST request
        ResponseEntity<String> responseEntity = restTemplate.exchange(urlEndpoint, HttpMethod.POST, requestEntity, String.class);
        if (responseEntity.getStatusCode() == HttpStatus.NO_CONTENT) {
        	JSONObject res = new JSONObject();
            res.put("responseCode", HttpStatus.ACCEPTED);
            res.put("responseMessage", MESSAGE.SUCCESS);
//        	throw new HttpClientErrorException(HttpStatus.OK);
              response = res.toString();
        } else {
        	throw new HttpClientErrorException(HttpStatus.INTERNAL_SERVER_ERROR);
        }    
		      return response;
 }

	
	public String getUserSessions(String userId) {
        try {
        	
        	String token = keyCloakTokenAccess();
	        JSONObject jsonResponseObject = new JSONObject(token);
	        String accessToken = jsonResponseObject.getString("access_token");
            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Bearer " + accessToken);
            RestTemplate restTemplate = new RestTemplate();
            String sessionUrl = baseUrl + "/admin/realms/" + realms + "/users/" + userId + "/sessions";
            HttpEntity<String> requestEntity = new HttpEntity<>(headers);
            ResponseEntity<String> responseEntity = restTemplate.exchange(sessionUrl, HttpMethod.GET, requestEntity, String.class);
            return responseEntity.getBody(); // Session JSON Array
        } catch (Exception e) {
            
            return null;
        }
        
    }
	
	public String logoutAllUserSession( String userId) {
        String userCreateAPI = baseUrl + "/admin/realms/" + realms + "/users/" + userId + "/logout";
        String token = keyCloakTokenAccess();
        JSONObject jsonResponseObject = new JSONObject(token);
        String accessToken = jsonResponseObject.getString("access_token");        
        RestTemplate restTemplate = new RestTemplate();
     // Set the request headers
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "Bearer " + accessToken);        
        // Empty body for POST
        HttpEntity<String> requestEntity = new HttpEntity<>("", headers);
        // Make the HTTP POST request
        ResponseEntity<String> responseEntity = restTemplate.exchange(userCreateAPI, HttpMethod.POST, requestEntity, String.class);
        String response = null;
        if (responseEntity.getStatusCode() == HttpStatus.NO_CONTENT) {
        	JSONObject res = new JSONObject();
        	 res.put("responseCode", HttpStatus.ACCEPTED);
             res.put("responseMessage", MESSAGE.SUCCESS);
            response = res.toString();
        }       
        return response;
 }

}

