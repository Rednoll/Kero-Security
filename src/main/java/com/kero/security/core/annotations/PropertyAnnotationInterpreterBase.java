package com.kero.security.core.annotations;

import com.kero.security.core.KeroAccessManager;

public abstract class PropertyAnnotationInterpreterBase<A> implements PropertyAnnotationInterpreter<A> {

	protected KeroAccessManager manager;
	
	public PropertyAnnotationInterpreterBase(KeroAccessManager manager) {
		
		this.manager = manager;
	}
}
