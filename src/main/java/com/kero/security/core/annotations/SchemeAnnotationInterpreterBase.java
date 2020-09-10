package com.kero.security.core.annotations;

import com.kero.security.core.KeroAccessAgent;

public abstract class SchemeAnnotationInterpreterBase<A> implements SchemeAnnotationInterpreter<A> {

	protected KeroAccessAgent agent;
	
	public SchemeAnnotationInterpreterBase(KeroAccessAgent agent) {
		
		this.agent = agent;
	}
}
