package com.kero.security.lang.nodes;

import java.util.Set;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.property.Property;
import com.kero.security.core.role.Role;
import com.kero.security.core.rules.rolebased.GrantAccessRule;

public class GrantAccessRuleNode extends RoleBasedAccessRuleNode {

	public GrantAccessRuleNode(Set<String> roleNames) {
		super(roleNames);
		
	}
	
	public void interpret(KeroAccessAgent manager, Property property) {
		
		if(roleNames.isEmpty()) return;
		
		Set<Role> roles = manager.getOrCreateRole(roleNames);
		
		property.addRule(new GrantAccessRule(roles));
	}
}
