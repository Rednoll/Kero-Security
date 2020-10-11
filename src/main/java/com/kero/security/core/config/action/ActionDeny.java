package com.kero.security.core.config.action;

import java.lang.reflect.Method;

import com.kero.security.core.exception.AccessException;
import com.kero.security.core.scheme.AccessScheme;

public class ActionDeny extends ActionBase implements Action {

	public ActionDeny(AccessScheme scheme) {
		super(scheme);
		
	}

	@Override
	public Object process(Method method, Object original, Object[] args) {
		
		throw new AccessException("Access denied for: "+scheme.getAgent().extractPropertyName(method.getName()));
	}
}