package com.kero.security.core.property.annotations;

import com.kero.security.core.KeroAccessAgent;
import com.kero.security.core.annotations.SchemeAnnotationInterpreterBase;
import com.kero.security.core.scheme.configuration.AccessSchemeConfigurator;

public class EnableInheritPropertiesInterpreter extends SchemeAnnotationInterpreterBase<DisableInheritProperties> {

	public EnableInheritPropertiesInterpreter(KeroAccessAgent agent) {
		super(agent);
	
	}

	@Override
	public void interpret(AccessSchemeConfigurator configurator, DisableInheritProperties annotation) {
	
		configurator.enableInherit();
	}
}
