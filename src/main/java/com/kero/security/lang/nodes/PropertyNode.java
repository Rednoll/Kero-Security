package com.kero.security.lang.nodes;

import java.util.HashSet;
import java.util.Set;

import com.kero.security.core.property.Property;
import com.kero.security.core.role.Role;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.rules.AccessRuleImpl;
import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.managers.KeroAccessManager;

public class PropertyNode extends KsdlNodeBase {

	private String name;
	private Boolean defaultRule;
	
	private Set<String> grantRoleNames;
	private Set<String> denyRoleNames;
	
	public PropertyNode(String name, Boolean defaultRule, Set<String> grantRoleNames, Set<String> denyRoleNames) {
		
		this.name = name;
		this.defaultRule = defaultRule;
		
		this.grantRoleNames = grantRoleNames;
		this.denyRoleNames = denyRoleNames;
	}

	public void interpret(AccessScheme scheme) {
		
		KeroAccessManager manager = scheme.getManager();
		
		Property prop = scheme.getOrCreateLocalProperty(name);
		
		if(defaultRule != null) {
			
			prop.setDefaultRule(defaultRule ? AccessRule.GRANT_ALL : AccessRule.DENY_ALL);
		}
		
		Set<Role> grantRoles = new HashSet<>();

			for(String roleName : grantRoleNames) {
				
				grantRoles.add(manager.getOrCreateRole(roleName));
			}

		Set<Role> denyRoles = new HashSet<>();
			
			for(String roleName : denyRoleNames) {
				
				denyRoles.add(manager.getOrCreateRole(roleName));
			}
		
		AccessRule grantRule = new AccessRuleImpl(grantRoles, true);
		AccessRule denyRule = new AccessRuleImpl(denyRoles, false);
		
		prop.addRule(grantRule);
		prop.addRule(denyRule);
	}
}
