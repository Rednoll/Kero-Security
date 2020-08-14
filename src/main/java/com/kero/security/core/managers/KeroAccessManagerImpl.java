package com.kero.security.core.managers;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.kero.security.core.interceptor.DenyInterceptor;
import com.kero.security.core.interceptor.annotations.AddDenyInterceptor;
import com.kero.security.core.interceptor.annotations.DenyWithInterceptor;
import com.kero.security.core.property.annotations.DisableInheritProperties;
import com.kero.security.core.property.annotations.EnableInheritProperties;
import com.kero.security.core.role.Role;
import com.kero.security.core.role.RoleImpl;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.rules.AccessRuleImpl;
import com.kero.security.core.rules.annotations.DefaultDeny;
import com.kero.security.core.rules.annotations.DefaultGrant;
import com.kero.security.core.rules.annotations.DenyFor;
import com.kero.security.core.rules.annotations.GrantFor;
import com.kero.security.core.type.ProtectedType;
import com.kero.security.core.type.ProtectedTypeClass;
import com.kero.security.core.type.ProtectedTypeInterface;

public class KeroAccessManagerImpl implements KeroAccessManager {
	
	protected static Logger LOGGER = LoggerFactory.getLogger("KeroSecurity");
	
	protected Map<Class, ProtectedType> types = new HashMap<>();
	
	protected Map<String, Role> roles = new HashMap<>();
	
	protected AccessRule defaultRule = AccessRuleImpl.DENY_ALL;

	@Override
	public Role createRole(String name, int priority) {
		
		if(hasRoleWithPriority(priority)) throw new RuntimeException("Role with priority: "+priority+" already exists!");
		
		Role role = new RoleImpl(name, priority);
		
		roles.put(name, role);
		
		return role;
	}
	
	public Role getRole(String name) {
		
		return roles.get(name);
	}
	
	public Role getOrCreateRole(String name) {
		
		if(hasRole(name)) {
			
			return getRole(name);
		}
		else {
			
			Role withMaxPriority = getRoleWithMaxPriorty();
			int priority = withMaxPriority != null ? withMaxPriority.getPriority() + 1 : 1;
			
			return createRole(name, priority);
		}
	}
	
	public Role getRoleWithMaxPriorty() {
		
		Role role = null;
		int max = Integer.MIN_VALUE;
		
		for(Role suspect : roles.values()) {
			
			if(suspect.getPriority() > max) {
				
				role = suspect;
				max = suspect.getPriority();
			}
		}
		
		return role;
	}
	
	public boolean hasRole(String name) {
		
		return this.roles.containsKey(name);
	}
	
	public boolean hasRoleWithPriority(int priority) {
		
		for(Role role : roles.values()) {
			
			if(role.getPriority() == priority) {
				
				return true;
			}
		}
		
		return false;
	}
	
	@Override
	public boolean hasType(Class<?> rawType) {
		
		return types.containsKey(rawType);
	}

	@Override
	public ProtectedType getType(Class<?> rawType) {
		
		return types.get(rawType);
	}
	
	@Override
	public ObjectTypeAccessManager type(Class<?> rawType) {
		
		try {
			
			return new ObjectTypeAccessManager(this, getOrCreateType(rawType));
		}
		catch(Exception e) {
			
			throw new RuntimeException(e);
		}
	}
	
	public ProtectedType getOrCreateType(Class<?> rawType){
		
		return hasType(rawType) ? getType(rawType) : createType(rawType);
	}
	
	public ProtectedType createType(Class<?> rawType) {
		
		ProtectedType type = null;
		
		if(rawType.isInterface()) {
			
			LOGGER.debug("Creating protected type INTERFACE for: "+rawType.getCanonicalName());
			type = new ProtectedTypeInterface(this, rawType);
		}
		else {
			
			try {
				
				LOGGER.debug("Creating protected type CLASS for: "+rawType.getCanonicalName());
				type = new ProtectedTypeClass(this, rawType);
			}
			catch(Exception e) {
				
				throw new RuntimeException(e);
			}
		}
		
		processAnnotations(rawType, type);
		
		types.put(rawType, type);
		
		return type;
	}
	
	protected void processAnnotations(Class<?> rawType, ProtectedType type) {
		
		ObjectTypeAccessManager typeAccess = new ObjectTypeAccessManager(this, type);
		
		if(rawType.isAnnotationPresent(DefaultGrant.class)) {
			
			typeAccess.defaultGrant();
		}
		else if(rawType.isAnnotationPresent(DefaultDeny.class)) {
			
			typeAccess.defaultDeny();
		}
		
		if(rawType.isAnnotationPresent(DisableInheritProperties.class)) {
			
			typeAccess.disableInherit();
		}
		
		if(rawType.isAnnotationPresent(EnableInheritProperties.class)) {
			
			typeAccess.enableInherit();
		}
		
		Map<String, List<Object>> propertyAnnotations = new HashMap<>();
		
		//Scan fields
		Field[] fields = rawType.getDeclaredFields();
		
		for(Field field : fields) {
			
			String name = extractName(field.getName());
			
			Annotation[] annotations = field.getAnnotations();
		
			if(!propertyAnnotations.containsKey(name)) {
				
				propertyAnnotations.put(name, new LinkedList<>());
			}
			
			propertyAnnotations.get(name).addAll(Arrays.asList(annotations));
		}
		
		//Scan methods
		Method[] methods = rawType.getMethods();
		
		for(Method method : methods) {
			
			String name = extractName(method.getName());
			
			Annotation[] annotations = method.getAnnotations();
			
			if(!propertyAnnotations.containsKey(name)) {
				
				propertyAnnotations.put(name, new LinkedList<>());
			}
			
			propertyAnnotations.get(name).addAll(Arrays.asList(annotations));
		}
		
		propertyAnnotations.forEach((name, annotations)-> {
			
			SinglePropertyAccessManager propertyAccess = typeAccess.property(name);
			
			annotations.forEach((rawAnnotation)-> {
				
				if(rawAnnotation instanceof GrantFor) {
					
					GrantFor annotation = (GrantFor) rawAnnotation;
				
					String[] roles = annotation.value();
					
					propertyAccess
						.grantFor(roles);
				}
				else if(rawAnnotation instanceof DenyFor) {
					
					DenyFor annotation = (DenyFor) rawAnnotation;
				
					String[] roles = annotation.value();
					
					propertyAccess
						.denyFor(roles);
				}
				else if(rawAnnotation instanceof DefaultGrant) {
					
					propertyAccess
						.defaultGrant();
				}
				else if(rawAnnotation instanceof DefaultDeny) {
					
					propertyAccess
						.defaultGrant();
				}
				else if(rawAnnotation instanceof AddDenyInterceptor) {
					
					AddDenyInterceptor annotation = (AddDenyInterceptor) rawAnnotation;
					
					Set<Role> roles = new HashSet<>();
					
					for(String roleName : annotation.roles()) {
						
						roles.add(getOrCreateRole(roleName));
					}
					
					Class<? extends DenyInterceptor> interceptorClass = annotation.value();
					
					DenyInterceptor interceptor;
					
					try {
						
						interceptor = interceptorClass.getConstructor().newInstance();
					}
					catch(Exception e) {
						
						throw new RuntimeException(e);
					}
					
					interceptor.setRoles(roles);
					
					propertyAccess
						.addDenyInterceptor(interceptor);
				}
				else if(rawAnnotation instanceof DenyWithInterceptor) {
					
					DenyWithInterceptor annotation = (DenyWithInterceptor) rawAnnotation;
					
					Set<Role> roles = new HashSet<>();
					
					for(String roleName : annotation.roles()) {
						
						roles.add(getOrCreateRole(roleName));
					}
					
					Class<? extends DenyInterceptor> interceptorClass = annotation.value();
					
					DenyInterceptor interceptor;
					
					try {
						
						interceptor = interceptorClass.getConstructor().newInstance();
					}
					catch(Exception e) {
						
						throw new RuntimeException(e);
					}
					
					interceptor.setRoles(roles);
					
					propertyAccess
						.denyWithInterceptor(interceptor);
				}
			});
		});
	}
	
	@Override
	public <T> T protect(T object, Set<Role> roles) {
		
		try {
			
			ProtectedTypeClass protectedType = (ProtectedTypeClass) getOrCreateType(object.getClass());
				
			return protectedType.protect(object, roles);
		}
		catch(Exception e) {
			
			throw new RuntimeException(e);
		}
	}
	
	public String extractName(String rawName) {
		
		if(rawName.startsWith("get")) {
			
			rawName = rawName.replaceFirst("get", "");
		}
		
		rawName = rawName.toLowerCase();
	
		return rawName;
	}
	
	public AccessRule getDefaultRule() {
		
		return this.defaultRule;
	}
}
