package com.kero.security.lang.nodes;

import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.property.Property;
import com.kero.security.core.role.Role;
import com.kero.security.core.rules.AccessRuleImpl;

public class AccessRuleNode extends KsdlNodeBase {

	private static Logger LOGGER = LoggerFactory.getLogger("KeroSecurity");
	
	public static final AccessRuleNode EMPTY = new Empty();
	
	private Set<String> roleNames;
	private boolean accessible;
	
	public AccessRuleNode(Set<String> roleNames, boolean accessible) {
		
		this.roleNames = roleNames;
		this.accessible = accessible;
	}
	
	public void interpret(KeroAccessAgent manager, Property property) {
		
		if(roleNames.isEmpty()) return;
		
		Set<Role> roles = manager.getOrCreateRole(roleNames);
		
		LOGGER.debug("Interpret access rule node to: "+property.getName()+" Accessible: "+this.accessible+" Roles: "+roles);
		
		property.addRule(new AccessRuleImpl(roles, this.accessible));
	}
	
	private static class Empty extends AccessRuleNode {

		public Empty() {
			super(null, false);
			
		}
		
		public void interpret(KeroAccessAgent manager, Property property) {
			
		}
	}
}
