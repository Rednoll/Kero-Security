package com.kero.security.core.property.annotations;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.annotations.SchemeAnnotationInterpreterBase;
import com.kero.security.core.scheme.configuration.AccessSchemeConfigurator;

public class DisableInheritInterpreter extends SchemeAnnotationInterpreterBase<DisableInherit> {

	public DisableInheritInterpreter(KeroAccessAgent agent) {
		super(agent);
	
	}

	@Override
	public void interpret(AccessSchemeConfigurator configurator, DisableInherit annotation) {
	
		configurator.disableInherit();
	}
}
