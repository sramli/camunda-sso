package org.camunda.bpm.engine.rest.security.auth.impl;

import org.camunda.bpm.common.security.keycloak.Keycloak;
import org.camunda.bpm.engine.ProcessEngine;
import org.camunda.bpm.engine.rest.security.auth.AuthenticationProvider;
import org.camunda.bpm.engine.rest.security.auth.AuthenticationResult;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class KeycloakAuthenticationProvider implements AuthenticationProvider {

    protected static final String BASIC_AUTH_HEADER_PREFIX = "Basic ";

    @Override
    public AuthenticationResult extractAuthenticatedUser(HttpServletRequest request, ProcessEngine engine) {
        try {
            Keycloak keycloak = new Keycloak(request);
            keycloak.setProcessEngine(engine);
            keycloak.process();

            // only allow access, if the user has the camunda-api role
            if(keycloak.getCurrentUserRoles().contains("camunda-api")) {
                return AuthenticationResult.successful(keycloak.getCurrentUser().get().getId());
            } else {
                return AuthenticationResult.unsuccessful(keycloak.getCurrentUser().get().getId());
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            return AuthenticationResult.unsuccessful();
        }
    }

    @Override
    public void augmentResponseByAuthenticationChallenge(HttpServletResponse response, ProcessEngine engine) {
        // response.setHeader("Authenticate", BASIC_AUTH_HEADER_PREFIX + "realm=\"" + engine.getName() + "\"");
    }
}
