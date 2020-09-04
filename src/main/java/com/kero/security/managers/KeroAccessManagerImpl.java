package com.kero.security.managers;

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
import com.kero.security.core.role.annotations.PropagateRole;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.rules.AccessRuleImpl;
import com.kero.security.core.rules.annotations.DefaultDeny;
import com.kero.security.core.rules.annotations.DefaultGrant;
import com.kero.security.core.rules.annotations.DenyFor;
import com.kero.security.core.rules.annotations.GrantFor;
import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.core.scheme.ClassAccessScheme;
import com.kero.security.core.scheme.InterfaceAccessScheme;

import io.github.classgraph.ClassGraph;
import io.github.classgraph.ClassInfo;
import io.github.classgraph.ClassInfoList;
import io.github.classgraph.ScanResult;

public class KeroAccessManagerImpl implements KeroAccessManager {
	
	protected static Logger LOGGER = LoggerFactory.getLogger("KeroSecurity");
	
	protected Map<Class, AccessScheme> schemes = new HashMap<>();
	
	protected Map<String, Role> roles = new HashMap<>();
	
	protected AccessRule defaultRule = AccessRuleImpl.GRANT_ALL;
	
	protected ClassLoader proxiesClassLoader = ClassLoader.getSystemClassLoader();
	
	protected Set<Class> ignoreList = new HashSet<>();
	
	protected String basePackage = "com.kero";
	protected boolean scaned = false;
	
	protected Map<String, Class<?>> aliasedTypes = new HashMap<>();
	
	public KeroAccessManagerImpl() {
		
		ignoreType(String.class);
		
		ignoreType(Integer.class);
		ignoreType(int.class);
		
		ignoreType(Long.class);
		ignoreType(long.class);
		
		ignoreType(Float.class);
		ignoreType(float.class);
		
		ignoreType(Double.class);
		ignoreType(double.class);
		
		ignoreType(Character.class);
		ignoreType(char.class);
		
		ignoreType(Boolean.class);
		ignoreType(boolean.class);
	}
	
	public void addTypeAliase(String aliase, Class<?> type) {
		
		this.aliasedTypes.put(aliase, type);
	}
	
	public void setBasePackage(String basePackage) {
		
		this.basePackage = basePackage;
	}
	
	public void ignoreType(Class<?> type) {
		
		ignoreList.add(type);
	}
	
	@Override
	public Role createRole(String name) {
		
		Role role = new RoleImpl(name);
		
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

			return createRole(name);
		}
	}
	
	public boolean hasRole(String name) {
		
		return this.roles.containsKey(name);
	}
	
	@Override
	public boolean hasScheme(Class<?> rawType) {
		
		return schemes.containsKey(rawType);
	}

	@Override
	public AccessScheme getScheme(Class<?> rawType) {
		
		return schemes.get(rawType);
	}
	
	@Override
	public Class<?> getTypeByAliase(String aliase) {
		
		if(aliasedTypes.containsKey(aliase)) return aliasedTypes.get(aliase);
		
		if(!scaned) {
			
			LOGGER.debug("Begin scan base package: "+basePackage);
			
			ScanResult scanResult = new ClassGraph().verbose().enableAllInfo().acceptPackages(basePackage).scan();
			
			ClassInfoList classInfoList = scanResult.getAllClasses();
			
			for(ClassInfo typeInfo : classInfoList) {
				
				String typeAliase = typeInfo.getSimpleName();
				
				Class<?> type = typeInfo.loadClass();
				
				LOGGER.debug("Registered type: "+typeAliase);
				
				aliasedTypes.put(typeAliase, type);
			}
			
			scaned = true;
		}
		
		return aliasedTypes.get(aliase);
	}
	
	@Override
	public AccessSchemeManager scheme(Class<?> rawType) {
		
		try {
			
			return new AccessSchemeManager(this, getOrCreateScheme(rawType));
		}
		catch(Exception e) {
			
			throw new RuntimeException(e);
		}
	}
	
	public AccessScheme getOrCreateScheme(Class<?> rawType){
		
		return hasScheme(rawType) ? getScheme(rawType) : createScheme(rawType);
	}
	
	public AccessScheme createScheme(Class<?> rawType) {
		
		AccessScheme scheme = null;
		
		if(rawType.isInterface()) {
			
			LOGGER.debug("Creating access scheme for interface: "+rawType.getCanonicalName());
			scheme = new InterfaceAccessScheme(this, rawType);
		}
		else {
			
			LOGGER.debug("Creating access scheme for class: "+rawType.getCanonicalName());
			scheme = new ClassAccessScheme(this, rawType);
		}
		
		processAnnotations(rawType, scheme);
		
		schemes.put(rawType, scheme);
		
		return scheme;
	}
	
	protected void processAnnotations(Class<?> rawType, AccessScheme scheme) {
		
		AccessSchemeManager schemeAccess = new AccessSchemeManager(this, scheme);
		
		if(rawType.isAnnotationPresent(DefaultGrant.class)) {
			
			schemeAccess.defaultGrant();
		}
		else if(rawType.isAnnotationPresent(DefaultDeny.class)) {
			
			schemeAccess.defaultDeny();
		}
		
		if(rawType.isAnnotationPresent(DisableInheritProperties.class)) {
			
			schemeAccess.disableInherit();
		}
		
		if(rawType.isAnnotationPresent(EnableInheritProperties.class)) {
			
			schemeAccess.enableInherit();
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
			
			SinglePropertyManager propertyAccess = schemeAccess.property(name);
			
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
				else if(rawAnnotation instanceof PropagateRole) {
					
					PropagateRole annotation = (PropagateRole) rawAnnotation;

					propertyAccess
						.propagateRole(annotation.from(), annotation.to());
				}
			});
		});
	}
	
	@Override
	public <T> T protect(T object, Set<Role> roles) {
		
		if(object == null) return null;
		
		if(this.ignoreList.contains(object.getClass())) return object;

		try {
			
			ClassAccessScheme scheme = (ClassAccessScheme) getOrCreateScheme(object.getClass());
				
			return scheme.protect(object, roles);
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

	@Override
	public ClassLoader getClassLoader() {
		
		return this.proxiesClassLoader;
	}
}
