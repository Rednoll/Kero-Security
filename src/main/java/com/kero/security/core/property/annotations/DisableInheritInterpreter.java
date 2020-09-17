package com.kero.security.core.property.annotations;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.annotations.SchemeAnnotationInterpreterBase;
import com.kero.security.core.scheme.configurator.CodeAccessSchemeConfigurator;

public class DisableInheritInterpreter extends SchemeAnnotationInterpreterBase<DisableInherit> {

	public DisableInheritInterpreter(KeroAccessAgent agent) {
		super(agent);
	
	}

	@Override
	public void interpret(CodeAccessSchemeConfigurator configurator, DisableInherit annotation) {
	
		configurator.disableInherit();
	}
}
