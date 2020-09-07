package com.kero.security.core.rules.annotations;

import com.kero.security.core.KeroAccessManager;
import com.kero.security.core.annotations.PropertyAnnotationInterpreterBase;
import com.kero.security.core.annotations.SchemeAnnotationInterpreter;
import com.kero.security.core.scheme.configuration.AccessSchemeConfigurator;
import com.kero.security.core.scheme.configuration.SinglePropertyConfigurator;

public class DefaultGrantInterpreter extends PropertyAnnotationInterpreterBase<DefaultGrant> implements SchemeAnnotationInterpreter<DefaultGrant> {

	public DefaultGrantInterpreter(KeroAccessManager manager) {
		super(manager);
	
	}

	@Override
	public void interpret(SinglePropertyConfigurator configurator, DefaultGrant annotation) {
		
		configurator.defaultGrant();
	}

	@Override
	public void interpret(AccessSchemeConfigurator configurator, DefaultGrant annotation) {
		
		configurator.defaultGrant();
	}
}
