package com.kero.security.core.scheme;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.config.PreparedAccessConfiguration;
import com.kero.security.core.config.PreparedAccessConfigurationImpl;
import com.kero.security.core.config.prepared.PreparedAction;
import com.kero.security.core.config.prepared.PreparedDenyRule;
import com.kero.security.core.config.prepared.PreparedGrantRule;
import com.kero.security.core.interceptor.DenyInterceptor;
import com.kero.security.core.property.Property;
import com.kero.security.core.role.Role;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.scheme.proxy.AdaptiveProxyAgent;
import com.kero.security.core.scheme.proxy.CustomProxyAgent;
import com.kero.security.core.scheme.proxy.ProxyAgent;
import com.kero.security.core.scheme.proxy.SubclassProxyAgent;
import com.kero.security.core.utils.ByteBuddyClassUtils;

public class ClassAccessScheme extends AccessSchemeBase implements InvocationHandler {

	private static Logger LOGGER = LoggerFactory.getLogger("Kero-Security");
	
	private ProxyAgent proxyAgent = null;
	
	private Map<Set<Role>, PreparedAccessConfiguration> configsCache = new HashMap<>();
	
	public ClassAccessScheme() {
		super();
	
	}
	
	public ClassAccessScheme(KeroAccessAgent agent, Class<?> type) {
		super(agent, type);
		
	}
	
	public ClassAccessScheme(KeroAccessAgent agent, String aliase, Class<?> type) {
		super(agent, aliase, type);
		
	}
	
	protected void initProxy() throws Exception {
		
		if(this.proxyAgent != null) return;
		
		if(!Modifier.isAbstract(type.getModifiers())) {
			
			LOGGER.debug("Building proxy for: "+type.getCanonicalName());
		
			this.proxyAgent = createProxyAgent();
		}
	}
	
	@Override
	public Object invoke(Object rawProxy, Method method, Object[] args) throws Throwable {
		
		AccessProxy proxy = (AccessProxy) rawProxy;
		
		Object original = proxy.getOriginal();
		PreparedAccessConfiguration pac = proxy.getConfiguration();
	
		return pac.process(original, method, args);
	}
	
	public <T> T protect(T object, Collection<Role> roles) throws Exception {
		
		if(this.proxyAgent == null) {
			
			initProxy();
		}
		
		PreparedAccessConfiguration config = configsCache.get(roles);
		
		if(config == null) {
	
			config = prepareAccessConfiguration(roles);
			configsCache.put(Collections.unmodifiableSet(new HashSet<>(roles)), config);
		}
		
		return (T) this.proxyAgent.wrap(object, config);
	}
	
	private PreparedAccessConfiguration prepareAccessConfiguration(Collection<Role> roles) {
		
		String rolesList = "[";
		
		for(Role role : roles) {
			
			rolesList += role.getName()+" ";
		}
		
		rolesList = rolesList.trim()+"]";
		
		LOGGER.debug("Prepare access configuration for "+type.getCanonicalName()+" roles: "+rolesList);
		
		Map<String, PreparedAction> preparedActions = new HashMap<>();

		Set<Property> properties = getProperties();
		
		properties.forEach((property)-> {
			
			Set<Role> significantRoles = new HashSet<>(roles);
			
			String propertyName = property.getName();
			List<AccessRule> rules = property.getRules();
			
			for(AccessRule rule : rules) {
 
				if(!rule.manage(significantRoles)) continue;
				
				if(rule.accessible(significantRoles)) {

					preparedActions.put(propertyName, new PreparedGrantRule(this, property.propagateRoles(roles)));
					return;
				}
				else if(rule.isDisallower()) {
 
					significantRoles.removeAll(rule.getRoles());
				}
			}
			
			DenyInterceptor interceptor = determineInterceptor(property, roles);
			
			if(interceptor != null) {
				
				preparedActions.put(propertyName, interceptor.prepare(roles));
				return;
			}
			
			if(!roles.isEmpty() && significantRoles.isEmpty()) {
			
				preparedActions.put(propertyName, new PreparedDenyRule(this));
				return;
			}

			if(property.hasDefaultRule()) {
			
				preparedActions.put(propertyName, property.getDefaultRule().prepare(this, roles));
				return;
			}
			else {
				
				AccessRule defaultRule = determineDefaultRule();
				
				preparedActions.put(propertyName, defaultRule.prepare(this, roles));
				return;
			}
		});
		
		PreparedAction defaultTypeAction = determineDefaultRule().prepare(this, roles);
		
		return new PreparedAccessConfigurationImpl(this, preparedActions, defaultTypeAction);
	}
	
	private DenyInterceptor determineInterceptor(Property property, Collection<Role> roles) {
	
		int maxOverlap = 0;
		int minTrash = Integer.MAX_VALUE;
		DenyInterceptor result = null;
		
		for(DenyInterceptor interceptor : property.getInterceptors()) {
			
			Set<Role> interceptorRoles = interceptor.getRoles();
			
			int overlap = 0;
			int trash = 0;
			
			for(Role interceptorRole : interceptorRoles) {
				
				if(roles.contains(interceptorRole)) {
					
					overlap++;
				}
				else {
					
					trash++;
				}
			}
			
			if(overlap > maxOverlap) {
				
				maxOverlap = overlap;
				minTrash = trash;
				result = interceptor;
			}
			else if(overlap == maxOverlap && trash < minTrash) {
				
				maxOverlap = overlap;
				minTrash = trash;
				result = interceptor;
			}
		}
	
		if(maxOverlap == 0) {
			
			return property.getDefaultInterceptor();
		}
		
		return result;
	}
	
	private AccessRule determineDefaultRule() {
		
		if(this.hasDefaultRule()) return this.getDefaultRule();
		
		if(this.inherit) {
			
			Class<?> superClass = this.type.getSuperclass();
			
			while(superClass != Object.class) {
				
				if(agent.hasScheme(superClass)) {
					
					AccessScheme scheme = agent.getScheme(superClass);
				
					if(scheme.hasDefaultRule()) {
						
						return scheme.getDefaultRule();
					}
				}
				
				superClass = superClass.getSuperclass();
			}
		}
		
		return agent.getDefaultRule();
	}
	
	public void collectProperties(Map<String, Property> complexProperties) {
		
		collectLocalProperties(complexProperties);
		
		if(this.inherit) {
			
			collectFromInterfaces(complexProperties);
			collectPropertiesFromSuperclass(complexProperties);
		}
	}
	
	protected void collectPropertiesFromSuperclass(Map<String, Property> complexProperties) {
		
		Class<?> superClass = type.getSuperclass();
		
		while(superClass != Object.class) {
			
			AccessScheme supeclassScheme = agent.getOrCreateScheme(superClass);

			supeclassScheme.collectProperties(complexProperties);

			superClass = superClass.getSuperclass();
		}
	}
	
	public void setProxyClass(Class<? extends AccessProxy> proxyClass) {
		
		this.proxyAgent = CustomProxyAgent.create(this, proxyClass);
	}
	
	public ProxyAgent createProxyAgent() { 
	
		boolean accessible = ByteBuddyClassUtils.checkAccessible(this.type);
		
		if(!Modifier.isFinal(this.type.getModifiers()) && accessible) {
			
			return SubclassProxyAgent.create(this);
		}
		else {
			
			return AdaptiveProxyAgent.create(this);
		}
	}
}
