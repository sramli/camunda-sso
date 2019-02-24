package org.camunda.bpm.common.security.keycloak;

import static org.camunda.bpm.engine.authorization.Authorization.ANY;
import static org.camunda.bpm.engine.authorization.Authorization.AUTH_TYPE_GRANT;
import static org.camunda.bpm.engine.authorization.Permissions.ALL;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;

import org.camunda.bpm.BpmPlatform;
import org.camunda.bpm.engine.AuthorizationService;
import org.camunda.bpm.engine.IdentityService;
import org.camunda.bpm.engine.ProcessEngine;
import org.camunda.bpm.engine.authorization.Resource;
import org.camunda.bpm.engine.authorization.Resources;
import org.camunda.bpm.engine.identity.Group;
import org.camunda.bpm.engine.identity.Tenant;
import org.camunda.bpm.engine.identity.User;
import org.camunda.bpm.engine.impl.persistence.entity.AuthorizationEntity;
import org.camunda.bpm.engine.impl.persistence.entity.TenantEntity;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessToken.Access;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import lombok.Data;

@Data
public class Keycloak {

    /**
     * Logger
     */
    private static Logger logger = LoggerFactory.getLogger(Keycloak.class.getName());

    /**
     * The Servlet Request
     */
    private ServletRequest request;

    /**
     * The HTTP Servlet Request
     */
    private HttpServletRequest req;

    /**
     * The Camunda Process Engine
     */
    public ProcessEngine processEngine;

    /**
     * The Camunda Authorization Service
     */
    private AuthorizationService authorizationService;

    /**
     * The Camunda Identity Service
     */
    private IdentityService identityService;

    /**
     * The currently signed in User
     */
    private Optional<User> currentUser = Optional.empty();

    /**
     * Client Roles of the current user
     */
    private Set<String> currentUserRoles = new HashSet<>();
    
    /**
     * Realm Roles of the current user
     */
    private Set<String> currentUserRealmRoles = new HashSet<>();

    /**
     * Tenants of the Current User
     */
    private Set<String> currentUserTenants = new HashSet<>();

    /**
     * Authorized Apps of the Current User
     */
    private HashSet<String> currentUserAuthorizedApps = new HashSet<>();

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
    public Keycloak(ServletRequest request) {
        // Initialize
        this.request = request;
        this.req = (HttpServletRequest) request;
        this.processEngine = getDefaultProcessEngine();
        this.authorizationService = processEngine.getAuthorizationService();
        this.identityService = processEngine.getIdentityService();
    }

    /**
     * Gets the UserName from KeyCloak
     * 
     * @return String The User Name
     */
    public Optional<String> getUserNameFromRequest() {
        // Check if camunda is initialized
        if (processEngine == null) {
            return Optional.empty();
        }

        // Query keycloak
        if (getToken() == null) {
        	setToken(((KeycloakPrincipal) req.getUserPrincipal()).getKeycloakSecurityContext().getToken());
        }

        return Optional.ofNullable(this.token.getPreferredUsername());
    }

    /**
     * Processes the Request using available informations
     */
    public void process() {
        // Check if camunda is initialized
        if (processEngine == null) {
            return;
        }

        // Query keycloak
        if (getToken() == null) {
        	KeycloakSecurityContext session = ((KeycloakPrincipal) req.getUserPrincipal()).getKeycloakSecurityContext();
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
        		
        		logger.info(String.format("Detected Client Roles [%s] for Client [%s]!", entry.getValue().getRoles(), entry.getKey()));
        		
        		Set<String> userRoles = entry.getValue().getRoles();
        		for(String role : userRoles) {
        			getCurrentUserRoles().add(role);
        		}
        	}
        } catch (Exception ex) {
        	// should never fail
        	ex.printStackTrace();
        }
        
        try {
        	Set<String> userRealmRoles = getToken().getRealmAccess().getRoles();
            setCurrentUserRealmRoles(userRealmRoles);
            
            logger.info(String.format("Detected Realm Roles [%s]!", getCurrentUserRealmRoles()));
        } catch (Exception ex) {
        	// will fail if the client can't access realm scoped roles
        	// ex.printStackTrace();
        }
        
        // create user in camunda if the user does not exist or update the existing user
        User user = identityService.createUserQuery().userId(userId).singleResult();
        if (user == null) {
            User newUser = identityService.newUser(userId);
            newUser.setPassword(java.util.UUID.randomUUID().toString());
            newUser.setFirstName(userNameFirst);
            newUser.setLastName(userNameLast);
            newUser.setEmail(userEmail);

            user = newUser;

            logger.info(String.format("Created Keycloak User [%s]!", newUser.getId()));
        } else {
            user.setFirstName(userNameFirst);
            user.setLastName(userNameLast);
            user.setEmail(userEmail);

            logger.info(String.format("Updated Keycloak User [%s]!", user.getId()));
        }

        // Save User to Camunda
        try {
            identityService.saveUser(user);
        } catch (Exception ex) {
        	ex.printStackTrace();
        	
        	logger.error(String.format("Failed to save user [%s]! Error: %s", user.getId(), ex.getMessage()));
        }

        // Store User
        setCurrentUser(Optional.ofNullable(user));

        // check user's app authorizations by iterating of list of apps
        getCurrentUserAuthorizedApps().add("welcome");

        // Create client roles (`camunda-` and `tenant-`)
        for (String role : getCurrentUserRoles()) {
            // Create Groups
            if (!role.startsWith("tenant-")) {
                Group group = identityService.createGroupQuery().groupId(role).singleResult();
                if (group == null) {
                    group = identityService.newGroup(role);
                    group.setName(role);

                    if (role.startsWith("camunda-")) {
                        group.setType("SYSTEM");
                    } else {
                        group.setType("WORKFLOW");
                    }
                    identityService.saveGroup(group);
                    logger.info(String.format("Added client group: [%s]!", group.getName()));
                }
            }

            // Create Tenants
            if (role.startsWith("tenant-")) {
                String tenantId = role.substring("tenant-".length());
                Tenant tenant = identityService.createTenantQuery().tenantId(tenantId).singleResult();
                if (tenant == null) {
                    tenant = new TenantEntity();
                    tenant.setId(tenantId);
                    tenant.setName(tenantId);
                    
                    identityService.saveTenant(tenant);
                    logger.info(String.format("Added tenant: [%s]!", tenant.getName()));
                }

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
        
        // sync group memberships
        List<Group> allGroups = identityService.createGroupQuery().list();
        for (Group group : allGroups) {
            // check if the user should have the current group
            if (getCurrentUserRoles().contains(group.getId())) {
                // check if the user already is a member
                if (identityService.createUserQuery().userId(getCurrentUser().get().getId()).memberOfGroup(group.getId()).count() == 0) {
                    // assign group, since the user doesn't have it
                    identityService.createMembership(getCurrentUser().get().getId(), group.getId());
                    logger.info(String.format("Added user [%s] to group [%s]!", getCurrentUser().get().getId(), group.getName()));
                }
            } else {
                identityService.deleteMembership(getCurrentUser().get().getId(), group.getId());

                // Remove groups without members
                if (identityService.createUserQuery().memberOfGroup(group.getId()).count() == 0) {
                    // Prevent removal of default admin group
                    if (!group.getId().equals("camunda-admin")) {
                        identityService.deleteGroup(group.getId());
                        
                        logger.info(String.format("Removed empty group [%s]!", group.getId()));
                    }
                }
            }
        }

        // sync tenant memberships
        List<Tenant> allTenants = identityService.createTenantQuery().list();
        for (Tenant tenant : allTenants) {
            // check if the user should have the current group
            if (getCurrentUserRoles().contains("tenant-" + tenant.getId())) {
                // check if the user should have the tenant
                if (identityService.createUserQuery().userId(getCurrentUser().get().getId()).memberOfTenant(tenant.getId()).count() == 0) {
                    // assign tenant, since the user doesn't have it
                    identityService.createTenantUserMembership(tenant.getId(), getCurrentUser().get().getId());
                    
                    logger.info(String.format("Added tenant-membership for [%s] to user [%s]!", tenant.getId(), getCurrentUser().get().getId()));
                }
            } else {
                identityService.deleteTenantUserMembership(tenant.getId(), getCurrentUser().get().getId());

                // Remove tenants without members
                if (identityService.createUserQuery().memberOfTenant(tenant.getId()).count() == 0) {
                    identityService.deleteTenant(tenant.getId());
                    
                    logger.info(String.format("Removed tenant without members [%s]!", tenant.getId()));
                }
            }
        }

        // grant all permissions to superadmin group
        for (Resource resource : Resources.values()) {
            String adminGroup = "camunda-admin";
            if (authorizationService.createAuthorizationQuery().groupIdIn(adminGroup).resourceType(resource).resourceId(ANY).count() == 0) {
                AuthorizationEntity adminGroupAuth = new AuthorizationEntity(AUTH_TYPE_GRANT);
                adminGroupAuth.setGroupId(adminGroup);
                adminGroupAuth.setResource(resource);
                adminGroupAuth.setResourceId(ANY);
                adminGroupAuth.addPermission(ALL);
                authorizationService.saveAuthorization(adminGroupAuth);

                logger.info(String.format("Permissions to Resource %s granted for group `camunda-admin`!", resource.resourceName()));
            }
        }
    }

    /**
     * Gets the ProcessEngine
     * <p>
     * Only works in single engine environment!
     * 
     * @return ProcessEngine The Default ProcessEngine
     */
    private ProcessEngine getDefaultProcessEngine() {
        return BpmPlatform.getDefaultProcessEngine();
    }

}
