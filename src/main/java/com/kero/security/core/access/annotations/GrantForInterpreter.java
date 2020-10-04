package com.kero.security.core.access.annotations;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.annotations.PropertyAnnotationInterpreterBase;
import com.kero.security.core.property.configurator.SinglePropertyConfigurator;

public class GrantForInterpreter extends PropertyAnnotationInterpreterBase<GrantFor> {

	public GrantForInterpreter(KeroAccessAgent agent) {
		super(agent);
	
	}

	@Override
	public void interpret(SinglePropertyConfigurator configurator, GrantFor annotation) {
		
		String[] roles = annotation.value();
		
		configurator
			.grantFor(roles);
	}
}
