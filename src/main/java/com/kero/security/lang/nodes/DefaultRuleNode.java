package com.kero.security.lang.nodes;

import com.kero.security.core.DefaultAccessOwner;
import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.rules.def.DefaultAccessRule;
import com.kero.security.core.rules.rolebased.RoleBasedAccessRule;

public enum DefaultRuleNode implements KsdlNode {
	
	EMPTY(null), GRANT(true), DENY(false);

	private Boolean accessible;
		
	private DefaultRuleNode(Boolean accessible) {
		
		this.accessible = accessible;
	}
	
	public void interpret(KeroAccessAgent manager, DefaultAccessOwner target) {
		
		if(accessible == null) {

			target.setDefaultAccess(null);
		}
		else if(accessible) {
			
			target.setDefaultAccess(DefaultAccessRule.GRANT_ALL);
		}
		else {
			
			target.setDefaultAccess(DefaultAccessRule.DENY_ALL);
		}
	}
}
