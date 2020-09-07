package com.kero.security.core.property.annotations;

import com.kero.security.core.KeroAccessManager;
import com.kero.security.core.annotations.SchemeAnnotationInterpreterBase;
import com.kero.security.core.scheme.configuration.AccessSchemeConfigurator;

public class EnableInheritPropertiesInterpreter extends SchemeAnnotationInterpreterBase<DisableInheritProperties> {

	public EnableInheritPropertiesInterpreter(KeroAccessManager manager) {
		super(manager);
	
	}

	@Override
	public void interpret(AccessSchemeConfigurator configurator, DisableInheritProperties annotation) {
	
		configurator.enableInherit();
	}
}
