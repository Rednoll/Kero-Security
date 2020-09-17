package com.kero.security.core.rules.annotations;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.annotations.PropertyAnnotationInterpreterBase;
import com.kero.security.core.annotations.SchemeAnnotationInterpreter;
import com.kero.security.core.property.configurator.SinglePropertyConfigurator;
import com.kero.security.core.scheme.configurator.CodeAccessSchemeConfigurator;

public class DefaultDenyInterpreter extends PropertyAnnotationInterpreterBase<DefaultDeny> implements SchemeAnnotationInterpreter<DefaultDeny> {

	public DefaultDenyInterpreter(KeroAccessAgent agent) {
		super(agent);
	
	}

	@Override
	public void interpret(SinglePropertyConfigurator configurator, DefaultDeny annotation) {
		
		configurator.defaultDeny();
	}

	@Override
	public void interpret(CodeAccessSchemeConfigurator configurator, DefaultDeny annotation) {
		
		configurator.defaultDeny();
	}
}
