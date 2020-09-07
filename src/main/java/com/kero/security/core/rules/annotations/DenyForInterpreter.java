package com.kero.security.core.rules.annotations;

import com.kero.security.core.KeroAccessManager;
import com.kero.security.core.annotations.PropertyAnnotationInterpreterBase;
import com.kero.security.core.scheme.configuration.SinglePropertyConfigurator;

public class DenyForInterpreter extends PropertyAnnotationInterpreterBase<DenyFor> {

	public DenyForInterpreter(KeroAccessManager manager) {
		super(manager);
	
	}

	@Override
	public void interpret(SinglePropertyConfigurator configurator, DenyFor annotation) {
		
		String[] roles = annotation.value();
		
		configurator
			.denyFor(roles);
	}
}
