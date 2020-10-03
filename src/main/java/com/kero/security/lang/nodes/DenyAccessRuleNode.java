package com.kero.security.lang.nodes;

import java.util.Set;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.property.Property;
import com.kero.security.core.role.Role;
import com.kero.security.core.rules.rolebased.DenyAccessRule;

public class DenyAccessRuleNode extends RoleBasedAccessRuleNode {

	public DenyAccessRuleNode(Set<String> roleNames) {
		super(roleNames);
		
	}
	
	public void interpret(KeroAccessAgent manager, Property property) {
		
		if(roleNames.isEmpty()) return;
		
		Set<Role> roles = manager.getOrCreateRole(roleNames);

		property.addRule(new DenyAccessRule(roles));
	}
}
