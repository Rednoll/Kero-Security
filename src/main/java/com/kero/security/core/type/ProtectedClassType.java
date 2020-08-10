package com.kero.security.core.type;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.util.Set;

import com.kero.security.core.role.Role;

public interface ProtectedClassType extends ProtectedType, InvocationHandler {

	public Object protect(Object obj, Set<Role> roles) throws Exception;
	public Object invoke(Object proxy, Method method, Object[] args) throws Throwable;
}
