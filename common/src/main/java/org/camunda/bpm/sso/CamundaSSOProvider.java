package org.camunda.bpm.sso;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
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

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.camunda.bpm.engine.authorization.Authorization.ANY;
import static org.camunda.bpm.engine.authorization.Authorization.AUTH_TYPE_GRANT;
import static org.camunda.bpm.engine.authorization.Permissions.ALL;

@Data
@Slf4j
public abstract class CamundaSSOProvider {

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
     * Gets the ProcessEngine
     * <p>
     * Only works in single engine environment!
     *
     * @return ProcessEngine The Default ProcessEngine
     */
    protected ProcessEngine getDefaultProcessEngine() {
        return BpmPlatform.getDefaultProcessEngine();
    }

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
     * Constructor
     *
     * @param request ServletRequest
     */
    public CamundaSSOProvider(ServletRequest request) {
        // Initialize
        this.request = request;
        this.req = (HttpServletRequest) request;
        this.processEngine = getDefaultProcessEngine();
        this.authorizationService = processEngine.getAuthorizationService();
        this.identityService = processEngine.getIdentityService();
    }

    /**
     * Creates a Group, if it's not existing yet
     */
    public void createGroup(String groupId) {
        Group group = getIdentityService().createGroupQuery().groupId(groupId).singleResult();
        if (group == null) {
            group = getIdentityService().newGroup(groupId);
            group.setName(groupId);

            if (groupId.startsWith("camunda-")) {
                group.setType("SYSTEM");
            } else {
                group.setType("WORKFLOW");
            }
            getIdentityService().saveGroup(group);

            log.info(String.format("Added client group: [%s]!", group.getName()));
        }
    }

    /**
     * Creates a Tenant, if it's not existing yet
     */
    public void createTenant(String tenantId) {
        Tenant tenant = getIdentityService().createTenantQuery().tenantId(tenantId).singleResult();
        if (tenant == null) {
            tenant = new TenantEntity();
            tenant.setId(tenantId);
            tenant.setName(tenantId);

            getIdentityService().saveTenant(tenant);
            log.info(String.format("Added tenant: [%s]!", tenant.getName()));
        }
    }

    /**
     * Syncs the group memerships for the current user
     */
    public void syncGroupMembershipForCurrentUser() {
        List<Group> allGroups = getIdentityService().createGroupQuery().list();
        for (Group group : allGroups) {
            // check if the user should have the current group
            if (getCurrentUserRoles().contains(group.getId())) {
                // check if the user already is a member
                if (getIdentityService().createUserQuery().userId(getCurrentUser().get().getId()).memberOfGroup(group.getId()).count() == 0) {
                    // assign group, since the user doesn't have it
                    getIdentityService().createMembership(getCurrentUser().get().getId(), group.getId());
                    log.info(String.format("Added user [%s] to group [%s]!", getCurrentUser().get().getId(), group.getName()));
                }
            } else {
                getIdentityService().deleteMembership(getCurrentUser().get().getId(), group.getId());

                // Remove groups without members
                if (getIdentityService().createUserQuery().memberOfGroup(group.getId()).count() == 0) {
                    // Prevent removal of default admin group
                    if (!group.getId().equals("camunda-admin")) {
                        getIdentityService().deleteGroup(group.getId());

                        log.info(String.format("Removed empty group [%s]!", group.getId()));
                    }
                }
            }
        }
    }

    /**
     * Syncs the tenants for the current user
     */
    public void syncTenantMembershipForCurrentUser() {
        List<Tenant> allTenants = getIdentityService().createTenantQuery().list();
        for (Tenant tenant : allTenants) {
            // check if the user should have the current group
            if (getCurrentUserRoles().contains("tenant-" + tenant.getId())) {
                // check if the user should have the tenant
                if (getIdentityService().createUserQuery().userId(getCurrentUser().get().getId()).memberOfTenant(tenant.getId()).count() == 0) {
                    // assign tenant, since the user doesn't have it
                    getIdentityService().createTenantUserMembership(tenant.getId(), getCurrentUser().get().getId());

                    log.info(String.format("Added tenant-membership for [%s] to user [%s]!", tenant.getId(), getCurrentUser().get().getId()));
                }
            } else {
                getIdentityService().deleteTenantUserMembership(tenant.getId(), getCurrentUser().get().getId());

                // Remove tenants without members
                if (getIdentityService().createUserQuery().memberOfTenant(tenant.getId()).count() == 0) {
                    getIdentityService().deleteTenant(tenant.getId());

                    log.info(String.format("Removed tenant without members [%s]!", tenant.getId()));
                }
            }
        }
    }

    /**
     * Creates the default permission groups, if they aren't existing
     */
    public void createDefaultPermissions() {
        for (Resource resource : Resources.values()) {
            String adminGroup = "camunda-admin";
            if (getAuthorizationService().createAuthorizationQuery().groupIdIn(adminGroup).resourceType(resource).resourceId(ANY).count() == 0) {
                AuthorizationEntity adminGroupAuth = new AuthorizationEntity(AUTH_TYPE_GRANT);
                adminGroupAuth.setGroupId(adminGroup);
                adminGroupAuth.setResource(resource);
                adminGroupAuth.setResourceId(ANY);
                adminGroupAuth.addPermission(ALL);
                getAuthorizationService().saveAuthorization(adminGroupAuth);

                log.info(String.format("Permissions to Resource %s granted for group `camunda-admin`!", resource.resourceName()));
            }
        }
    }

    /**
     * Gets the UserName from the request
     *
     * @return Username
     */
    public abstract Optional<String> getUserNameFromRequest();

    /**
     * Process Request
     */
    public abstract void process();

}
