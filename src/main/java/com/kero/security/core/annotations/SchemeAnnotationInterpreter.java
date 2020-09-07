package com.kero.security.core.annotations;

import com.kero.security.core.scheme.configuration.AccessSchemeConfigurator;

public interface SchemeAnnotationInterpreter<A> {

	public void interpret(AccessSchemeConfigurator configurator, A annotation);
}
