package com.kero.security.core.role.annotations;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.annotations.PropertyAnnotationInterpreterBase;
import com.kero.security.core.property.configurator.SinglePropertyConfigurator;

public class PropagateRolesInterpreter extends PropertyAnnotationInterpreterBase<PropagateRoles> {

	public PropagateRolesInterpreter(KeroAccessAgent agent) {
		super(agent);
	
	}

	@Override
	public void interpret(SinglePropertyConfigurator configurator, PropagateRoles annotation) {
	
		PropagateRole[] roles = annotation.value();
		
		if(roles == null) return;
	
		for(PropagateRole child : roles) {
			
			configurator
				.propagateRole(child.from(), child.to());
		}
	}
}
