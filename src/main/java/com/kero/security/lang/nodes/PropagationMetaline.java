package com.kero.security.lang.nodes;

import java.util.Map;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.property.Property;
import com.kero.security.core.role.Role;

public class PropagationMetaline extends PropertyMetalineBase {

	private Map<String, String> propagationMap;
	
	public PropagationMetaline(Map<String, String> propagationMap) {
		
		this.propagationMap = propagationMap;
	}
	
	public void interpret(KeroAccessAgent manager, Property property) {
		
		propagationMap.forEach((fromName, toName)-> {
		
			Role from = manager.getOrCreateRole(fromName);
			Role to = manager.getOrCreateRole(toName);
			
			property.addRolePropagation(from, to);
		});
	}
}
