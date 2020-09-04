package com.kero.security.lang.nodes;

import java.util.HashSet;
import java.util.Set;

import com.kero.security.core.property.Property;
import com.kero.security.core.role.Role;
import com.kero.security.core.rules.AccessRuleImpl;
import com.kero.security.managers.KeroAccessManager;

public class AccessRuleNode extends KsdlNodeBase {

	public static final AccessRuleNode EMPTY = new Empty();
	
	private Set<String> roleNames;
	private boolean accessible;
	
	public AccessRuleNode(Set<String> roleNames, boolean accessible) {
		
		this.roleNames = roleNames;
		this.accessible = accessible;
	}
	
	public void interpret(KeroAccessManager manager, Property property) {
		
		if(roleNames.isEmpty()) return;
		
		Set<Role> roles = new HashSet<>();
		
		for(String name : this.roleNames) {
			
			roles.add(manager.getOrCreateRole(name));
		}
		
		property.addRule(new AccessRuleImpl(roles, this.accessible));
	}
	
	private static class Empty extends AccessRuleNode {

		public Empty() {
			super(null, false);
			
		}
		
		public void interpret(KeroAccessManager manager, Property property) {
			
		}
	}
}
