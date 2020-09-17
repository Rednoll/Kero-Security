package com.kero.security.core.rules.annotations;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.annotations.PropertyAnnotationInterpreterBase;
import com.kero.security.core.annotations.SchemeAnnotationInterpreter;
import com.kero.security.core.property.configurator.SinglePropertyConfigurator;
import com.kero.security.core.scheme.configurator.CodeAccessSchemeConfigurator;

public class DefaultGrantInterpreter extends PropertyAnnotationInterpreterBase<DefaultGrant> implements SchemeAnnotationInterpreter<DefaultGrant> {

	public DefaultGrantInterpreter(KeroAccessAgent agent) {
		super(agent);
	
	}

	@Override
	public void interpret(SinglePropertyConfigurator configurator, DefaultGrant annotation) {
		
		configurator.defaultGrant();
	}

	@Override
	public void interpret(CodeAccessSchemeConfigurator configurator, DefaultGrant annotation) {
		
		configurator.defaultGrant();
	}
}
