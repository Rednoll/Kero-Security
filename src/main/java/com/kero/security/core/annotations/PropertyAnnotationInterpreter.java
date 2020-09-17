package com.kero.security.core.annotations;

import com.kero.security.core.property.configurator.SinglePropertyConfigurator;

public interface PropertyAnnotationInterpreter<A> {

	public void interpret(SinglePropertyConfigurator configurator, A annotation);
}
