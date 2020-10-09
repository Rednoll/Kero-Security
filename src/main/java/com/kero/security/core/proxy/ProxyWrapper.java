package com.kero.security.core.proxy;

import java.lang.reflect.Modifier;

import com.kero.security.core.config.PreparedAccessConfiguration;
import com.kero.security.core.utils.ByteBuddyClassUtils;

public interface ProxyWrapper {

	public Object wrap(Object obj, PreparedAccessConfiguration pac);

	public static ProxyWrapper create(Class<?> targetClass) {
		
		boolean accessible = ByteBuddyClassUtils.checkAccessible(targetClass);
		
		if(!Modifier.isFinal(targetClass.getModifiers()) && accessible) {
			
			return new SubclassProxyWrapper(targetClass);
		}
		else {
			
			return new AdaptiveProxyWrapper(targetClass);
		}
	}
}
