package com.kero.security.core.role.annotations;

import com.kero.security.core.KeroAccessManager;
import com.kero.security.core.annotations.PropertyAnnotationInterpreterBase;
import com.kero.security.core.scheme.configuration.SinglePropertyConfigurator;

public class PropagateRoleInterpreter extends PropertyAnnotationInterpreterBase<PropagateRole> {

	public PropagateRoleInterpreter(KeroAccessManager manager) {
		super(manager);
	
	}

	@Override
	public void interpret(SinglePropertyConfigurator configurator, PropagateRole annotation) {
	
		configurator
			.propagateRole(annotation.from(), annotation.to());
	}
}
