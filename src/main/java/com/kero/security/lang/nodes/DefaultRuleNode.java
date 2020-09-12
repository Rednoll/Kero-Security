package com.kero.security.lang.nodes;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.kero.security.core.DefaultRuleOwner;
import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.rules.AccessRule;

public enum DefaultRuleNode implements KsdlNode {
	
	EMPTY(null), GRANT(true), DENY(false);

	private static Logger LOGGER = LoggerFactory.getLogger("KeroSecurity");
	
	private Boolean accessible;
		
	private DefaultRuleNode(Boolean accessible) {
		
		this.accessible = accessible;
	}
	
	public void interpret(KeroAccessAgent manager, DefaultRuleOwner target) {
		
		if(accessible == null) {
			
			LOGGER.debug("Interpret default rule node to: "+target.getClass().getCanonicalName()+" NULL");
			
			target.setDefaultRule(null);
		}
		else if(accessible) {
			
			LOGGER.debug("Interpret default rule node to: "+target.getClass().getCanonicalName()+" GRANT");
			
			target.setDefaultRule(AccessRule.GRANT_ALL);
		}
		else {
			
			LOGGER.debug("Interpret default rule node to: "+target.getClass().getCanonicalName()+" DENY");
			
			target.setDefaultRule(AccessRule.DENY_ALL);
		}
	}
}
