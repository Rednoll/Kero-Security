package com.kero.security.core.scheme.configuration.auto;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import com.kero.security.core.KeroAccessManager;
import com.kero.security.core.annotations.PropertyAnnotationInterpreter;
import com.kero.security.core.annotations.SchemeAnnotationInterpreter;
import com.kero.security.core.interceptor.annotations.AddDenyInterceptor;
import com.kero.security.core.interceptor.annotations.AddDenyInterceptorInterpreter;
import com.kero.security.core.interceptor.annotations.DenyWithInterceptor;
import com.kero.security.core.interceptor.annotations.DenyWithInterceptorInterpreter;
import com.kero.security.core.property.annotations.DisableInheritProperties;
import com.kero.security.core.property.annotations.DisableInheritPropertiesInterpreter;
import com.kero.security.core.property.annotations.EnableInheritProperties;
import com.kero.security.core.property.annotations.EnableInheritPropertiesInterpreter;
import com.kero.security.core.role.annotations.PropagateRole;
import com.kero.security.core.rules.annotations.DefaultDeny;
import com.kero.security.core.rules.annotations.DefaultGrant;
import com.kero.security.core.rules.annotations.DenyFor;
import com.kero.security.core.rules.annotations.GrantFor;
import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.core.scheme.configuration.AccessSchemeConfigurator;
import com.kero.security.core.scheme.configuration.SinglePropertyConfigurator;

public class AnnotationAccessSchemeConfigurator extends AccessSchemeAutoConfiguratorBase {
	
	private Map<Class, SchemeAnnotationInterpreter> schemeInterpretors = new HashMap<>();
	private Map<Class, PropertyAnnotationInterpreter> proprtyInterpretors = new HashMap<>();
	
	public AnnotationAccessSchemeConfigurator(KeroAccessManager manager) {
		super(manager);
		
		proprtyInterpretors.put(AddDenyInterceptor.class, new AddDenyInterceptorInterpreter(this.manager));
		proprtyInterpretors.put(DenyWithInterceptor.class, new DenyWithInterceptorInterpreter(this.manager));
		
		schemeInterpretors.put(DisableInheritProperties.class, new DisableInheritPropertiesInterpreter(this.manager));
		schemeInterpretors.put(EnableInheritProperties.class, new EnableInheritPropertiesInterpreter(this.manager));
	}
	
	@Override
	public void configure(AccessScheme scheme) {
	
		if(!scheme.getManager().equals(this.manager)) throw new RuntimeException("Scheme from another manager! Can't be configured by this configurator.");
		
		Class<?> type = scheme.getTypeClass();
		
		AccessSchemeConfigurator schemeConfigurator = new AccessSchemeConfigurator(manager, scheme);
		
		if(type.isAnnotationPresent(DefaultGrant.class)) {
			
			schemeConfigurator.defaultGrant();
		}
		else if(type.isAnnotationPresent(DefaultDeny.class)) {
			
			schemeConfigurator.defaultDeny();
		}
		
		Map<String, List<Object>> propertyAnnotations = new HashMap<>();
		
		//Scan fields
		Field[] fields = type.getDeclaredFields();
		
		for(Field field : fields) {
			
			String name = manager.extractName(field.getName());
			
			Annotation[] annotations = field.getAnnotations();
		
			if(!propertyAnnotations.containsKey(name)) {
				
				propertyAnnotations.put(name, new LinkedList<>());
			}
			
			propertyAnnotations.get(name).addAll(Arrays.asList(annotations));
		}
		
		//Scan methods
		Method[] methods = type.getMethods();
		
		for(Method method : methods) {
			
			String name = manager.extractName(method.getName());
			
			Annotation[] annotations = method.getAnnotations();
			
			if(!propertyAnnotations.containsKey(name)) {
				
				propertyAnnotations.put(name, new LinkedList<>());
			}
			
			propertyAnnotations.get(name).addAll(Arrays.asList(annotations));
		}
		
		propertyAnnotations.forEach((name, annotations)-> {
			
			SinglePropertyConfigurator propertyAccess = schemeConfigurator.property(name);
			
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
				else if(rawAnnotation instanceof PropagateRole) {
					
					PropagateRole annotation = (PropagateRole) rawAnnotation;

					propertyAccess
						.propagateRole(annotation.from(), annotation.to());
				}
			});
		});
	}
}
