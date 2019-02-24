package org.camunda.bpm.common.security.keycloak;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;

import javax.servlet.ServletRequest;

import lombok.EqualsAndHashCode;
import lombok.extern.slf4j.Slf4j;
import org.camunda.bpm.engine.identity.User;
import org.camunda.bpm.sso.CamundaSSOProvider;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessToken.Access;

import lombok.Data;

@Data
@EqualsAndHashCode(callSuper = true)
@Slf4j
public class CamundaSSOKeycloak extends CamundaSSOProvider {

    /**
     * Access Token
     */
    private AccessToken token;
    
    /**
     * Keycloak System Clients
     */
    List<String> keycloakNativeClients = new ArrayList<>(Arrays.asList(
        "account",
        "admin-cli",
        "broker",
        "realm-management",
        "security-admin-console"
    ));
    
    /**
     * Constructor
     * 
     * @param request ServletRequest
     */
    public CamundaSSOKeycloak(ServletRequest request) {
        super(request);
    }

    /**
     * Gets the UserName from KeyCloak
     * 
     * @return String The User Name
     */
    public Optional<String> getUserNameFromRequest() {
        // Check if camunda is initialized
        if (processEngine == null) {
            log.error("Camunda BPM has not been initialized yet ... Authentication failed!");
            return Optional.empty();
        }

        // Query keycloak
        if (getToken() == null) {
        	setToken(((KeycloakPrincipal) getReq().getUserPrincipal()).getKeycloakSecurityContext().getToken());
        }

        return Optional.ofNullable(this.token.getPreferredUsername());
    }

    /**
     * Processes the Request using available informations
     */
    public void process() {
        // Check if camunda is initialized
        if (processEngine == null) {
            log.error("Camunda BPM has not been initialized yet ... Authentication failed!");
            return;
        }

        // Query keycloak
        if (getToken() == null) {
        	KeycloakSecurityContext session = ((KeycloakPrincipal) getReq().getUserPrincipal()).getKeycloakSecurityContext();
        	setToken(session.getToken());
        }
        
        // Load keycloak user information
        String userId = getToken().getPreferredUsername();
        String userNameFirst = getToken().getGivenName();
        String userNameLast = getToken().getFamilyName();
        String userEmail = getToken().getEmail();
        setCurrentUserRoles(new HashSet<>());
        try {
        	Map<String, Access> resourceAccess = getToken().getResourceAccess();
        	
        	for (Entry<String, Access> entry : resourceAccess.entrySet()) {
        		// skip system resources
        		if (getKeycloakNativeClients().contains(entry.getKey())) {
        			continue;
        		}
        		
        		log.info("User [{}] has the following roles [{}] in client [{}]!", userId, entry.getValue().getRoles(), entry.getKey());
        		
        		Set<String> userRoles = entry.getValue().getRoles();
        		for(String role : userRoles) {
        			getCurrentUserRoles().add(role);
        		}
        	}
        } catch (Exception ex) {
        	// should never fail, please report if it does
        	ex.printStackTrace();
        }
        
        try {
        	Set<String> userRealmRoles = getToken().getRealmAccess().getRoles();
            setCurrentUserRealmRoles(userRealmRoles);
            
            log.info(String.format("Detected Realm Roles [%s]!", getCurrentUserRealmRoles()));
        } catch (Exception ex) {
        	// will fail if the client can't access realm scoped roles in keycloak
        	// ex.printStackTrace();
        }
        
        // create user in camunda if the user does not exist or update the existing user
        User user = getIdentityService().createUserQuery().userId(userId).singleResult();
        if (user == null) {
            User newUser = getIdentityService().newUser(userId);
            newUser.setPassword(java.util.UUID.randomUUID().toString());
            newUser.setFirstName(userNameFirst);
            newUser.setLastName(userNameLast);
            newUser.setEmail(userEmail);

            user = newUser;

            log.info(String.format("Created Keycloak User [%s]!", newUser.getId()));
        } else {
            user.setFirstName(userNameFirst);
            user.setLastName(userNameLast);
            user.setEmail(userEmail);

            log.info(String.format("Updated Keycloak User [%s]!", user.getId()));
        }

        // Save User to Camunda
        try {
            getIdentityService().saveUser(user);
        } catch (Exception ex) {
        	ex.printStackTrace();
        	
        	log.error(String.format("Failed to save user [%s]! Error: %s", user.getId(), ex.getMessage()));
        }

        // Store User
        setCurrentUser(Optional.ofNullable(user));

        // check user's app authorizations by iterating of list of apps
        getCurrentUserAuthorizedApps().add("welcome");

        // Create client roles (`camunda-` and `tenant-`)
        for (String role : getCurrentUserRoles()) {
            // Create Groups
            if (!role.startsWith("tenant-")) {
                this.createGroup(role);
            }

            // Create Tenants
            if (role.startsWith("tenant-")) {
                String tenantId = role.substring("tenant-".length());
                this.createTenant(tenantId);

                // Store Tenants
                getCurrentUserTenants().add(tenantId);
            }

            // Application Auth
            if (role.equals("camunda-user")) {
                getCurrentUserAuthorizedApps().add("tasklist");
            }
            if (role.equals("camunda-operator")) {
                getCurrentUserAuthorizedApps().add("cockpit");
            }
            if (role.equals("camunda-admin")) {
                getCurrentUserAuthorizedApps().add("admin");
            }
        }
        
        // sync membership
        this.syncGroupMembershipForCurrentUser();
        this.syncTenantMembershipForCurrentUser();

        // grant all permissions to superadmin group
        this.createDefaultPermissions();
    }

}
