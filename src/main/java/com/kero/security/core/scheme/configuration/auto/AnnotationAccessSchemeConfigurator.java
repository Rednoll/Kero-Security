package com.kero.security.core.scheme.configuration.auto;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import com.kero.security.core.agent.KeroAccessAgent;
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
import com.kero.security.core.role.annotations.PropagateRoleInterpreter;
import com.kero.security.core.rules.annotations.DefaultDeny;
import com.kero.security.core.rules.annotations.DefaultDenyInterpreter;
import com.kero.security.core.rules.annotations.DefaultGrant;
import com.kero.security.core.rules.annotations.DefaultGrantInterpreter;
import com.kero.security.core.rules.annotations.DenyFor;
import com.kero.security.core.rules.annotations.DenyForInterpreter;
import com.kero.security.core.rules.annotations.GrantFor;
import com.kero.security.core.rules.annotations.GrantForInterpreter;
import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.core.scheme.configuration.AccessSchemeConfigurator;
import com.kero.security.core.scheme.configuration.SinglePropertyConfigurator;

public class AnnotationAccessSchemeConfigurator extends AccessSchemeAutoConfiguratorBase {
	
	private Map<Class, SchemeAnnotationInterpreter> schemeInterpreters = new HashMap<>();
	private Map<Class, PropertyAnnotationInterpreter> propertyInterpreters = new HashMap<>();
	
	public AnnotationAccessSchemeConfigurator(KeroAccessAgent agent) {
		
		schemeInterpreters.put(DisableInheritProperties.class, new DisableInheritPropertiesInterpreter(agent));
		schemeInterpreters.put(EnableInheritProperties.class, new EnableInheritPropertiesInterpreter(agent));
	
		propertyInterpreters.put(AddDenyInterceptor.class, new AddDenyInterceptorInterpreter(agent));
		propertyInterpreters.put(DenyWithInterceptor.class, new DenyWithInterceptorInterpreter(agent));
		propertyInterpreters.put(PropagateRole.class, new PropagateRoleInterpreter(agent));
		propertyInterpreters.put(DenyFor.class, new DenyForInterpreter(agent));
		propertyInterpreters.put(GrantFor.class, new GrantForInterpreter(agent));
		
		DefaultDenyInterpreter defaultDenyInterpreter = new DefaultDenyInterpreter(agent);
		
		schemeInterpreters.put(DefaultDeny.class, defaultDenyInterpreter);
		propertyInterpreters.put(DefaultDeny.class, defaultDenyInterpreter);
		
		DefaultGrantInterpreter defaultGrantInterpreter = new DefaultGrantInterpreter(agent);
		
		schemeInterpreters.put(DefaultGrant.class, defaultGrantInterpreter);
		propertyInterpreters.put(DefaultGrant.class, defaultGrantInterpreter);
	}
	
	@Override
	public void configure(AccessScheme scheme) {

		KeroAccessAgent agent = scheme.getAgent();
		
		Class<?> type = scheme.getTypeClass();
		
		AccessSchemeConfigurator schemeConfigurator = new AccessSchemeConfigurator(agent, scheme);
		
		for(Annotation annotation : type.getDeclaredAnnotations()) {
		
			if(schemeInterpreters.containsKey(annotation.annotationType())) {
				
				schemeInterpreters.get(annotation.annotationType()).interpret(schemeConfigurator, annotation);
			}
		}
		
		Map<String, List<Annotation>> propertyAnnotations = new HashMap<>();
		
		//Scan fields
		Field[] fields = type.getDeclaredFields();
		
		for(Field field : fields) {
			
			String name = agent.extractPropertyName(field.getName());
			
			Annotation[] annotations = field.getDeclaredAnnotations();
		
			if(!propertyAnnotations.containsKey(name)) {
				
				propertyAnnotations.put(name, new LinkedList<>());
			}
			
			propertyAnnotations.get(name).addAll(Arrays.asList(annotations));
		}
		
		//Scan methods
		Method[] methods = type.getMethods();
		
		for(Method method : methods) {
			
			String name = agent.extractPropertyName(method.getName());
			
			Annotation[] annotations = method.getDeclaredAnnotations();
			
			if(!propertyAnnotations.containsKey(name)) {
				
				propertyAnnotations.put(name, new LinkedList<>());
			}
			
			propertyAnnotations.get(name).addAll(Arrays.asList(annotations));
		}
		
		propertyAnnotations.forEach((name, annotations)-> {
			
			SinglePropertyConfigurator propertyConfigurator = schemeConfigurator.property(name);
			
			annotations.forEach((annotation)-> {

				if(propertyInterpreters.containsKey(annotation.annotationType())) {
					
					propertyInterpreters.get(annotation.annotationType()).interpret(propertyConfigurator, annotation);
				}
			});
		});
	}
}
