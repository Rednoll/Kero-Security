package com.kero.security.lang.nodes;

import com.kero.security.core.DefaultRuleOwner;
import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.rules.AccessRule;

public enum DefaultRuleNode implements KsdlNode {
	
	EMPTY(null), GRANT(true), DENY(false);

	private Boolean accessible;
		
	private DefaultRuleNode(Boolean accessible) {
		
		this.accessible = accessible;
	}
	
	public void interpret(KeroAccessAgent manager, DefaultRuleOwner target) {
		
		if(accessible == null) {

			target.setDefaultRule(null);
		}
		else if(accessible) {
			
			target.setDefaultRule(AccessRule.GRANT_ALL);
		}
		else {
			
			target.setDefaultRule(AccessRule.DENY_ALL);
		}
	}
}
