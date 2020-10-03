package com.kero.security.lang.nodes;

import java.util.Set;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.property.Property;

public abstract class RoleBasedAccessRuleNode extends KsdlNodeBase {

	public static final RoleBasedAccessRuleNode EMPTY = new Empty();
	
	protected Set<String> roleNames;
	
	public RoleBasedAccessRuleNode(Set<String> roleNames) {
		
		this.roleNames = roleNames;
	}
	
	public abstract void interpret(KeroAccessAgent manager, Property property);
	
	private static class Empty extends RoleBasedAccessRuleNode {

		public Empty() {
			super(null);
			
		}
		
		@Override
		public void interpret(KeroAccessAgent manager, Property property) {
			
		}
	}
}
