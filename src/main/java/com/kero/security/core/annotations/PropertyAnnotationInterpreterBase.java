package com.kero.security.core.annotations;

import com.kero.security.core.KeroAccessAgent;

public abstract class PropertyAnnotationInterpreterBase<A> implements PropertyAnnotationInterpreter<A> {

	protected KeroAccessAgent agent;
	
	public PropertyAnnotationInterpreterBase(KeroAccessAgent agent) {
		
		this.agent = agent;
	}
}
