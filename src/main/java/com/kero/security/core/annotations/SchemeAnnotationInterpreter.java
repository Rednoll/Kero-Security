package com.kero.security.core.annotations;

import com.kero.security.core.scheme.configurator.CodeAccessSchemeConfigurator;

public interface SchemeAnnotationInterpreter<A> {

	public void interpret(CodeAccessSchemeConfigurator configurator, A annotation);
}
