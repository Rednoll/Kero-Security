package com.kero.security.core.rules.annotations;

import com.kero.security.core.KeroAccessManager;
import com.kero.security.core.annotations.PropertyAnnotationInterpreterBase;
import com.kero.security.core.scheme.configuration.SinglePropertyConfigurator;

public class GrantForInterpreter extends PropertyAnnotationInterpreterBase<GrantFor> {

	public GrantForInterpreter(KeroAccessManager manager) {
		super(manager);
	
	}

	@Override
	public void interpret(SinglePropertyConfigurator configurator, GrantFor annotation) {
		
		String[] roles = annotation.value();
		
		configurator
			.grantFor(roles);
	}
}
