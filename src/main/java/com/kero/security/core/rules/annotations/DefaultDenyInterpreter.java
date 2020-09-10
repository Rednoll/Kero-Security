package com.kero.security.core.rules.annotations;

import com.kero.security.core.KeroAccessAgent;
import com.kero.security.core.annotations.PropertyAnnotationInterpreterBase;
import com.kero.security.core.annotations.SchemeAnnotationInterpreter;
import com.kero.security.core.scheme.configuration.AccessSchemeConfigurator;
import com.kero.security.core.scheme.configuration.SinglePropertyConfigurator;

public class DefaultDenyInterpreter extends PropertyAnnotationInterpreterBase<DefaultDeny> implements SchemeAnnotationInterpreter<DefaultDeny> {

	public DefaultDenyInterpreter(KeroAccessAgent agent) {
		super(agent);
	
	}

	@Override
	public void interpret(SinglePropertyConfigurator configurator, DefaultDeny annotation) {
		
		configurator.defaultDeny();
	}

	@Override
	public void interpret(AccessSchemeConfigurator configurator, DefaultDeny annotation) {
		
		configurator.defaultDeny();
	}
}
