package com.kero.security.core.annotations;

import com.kero.security.core.KeroAccessManager;

public abstract class SchemeAnnotationInterpreterBase<A> implements SchemeAnnotationInterpreter<A> {

	protected KeroAccessManager manager;
	
	public SchemeAnnotationInterpreterBase(KeroAccessManager manager) {
		
		this.manager = manager;
	}
}
