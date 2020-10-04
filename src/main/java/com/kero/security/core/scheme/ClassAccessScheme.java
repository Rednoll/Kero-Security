package com.kero.security.core.scheme;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.kero.security.core.access.annotations.Access;
import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.config.PreparedAccessConfiguration;
import com.kero.security.core.config.PreparedAccessConfigurationImpl;
import com.kero.security.core.config.prepared.PreparedAction;
import com.kero.security.core.config.prepared.PreparedDenyRule;
import com.kero.security.core.config.prepared.PreparedGrantRule;
import com.kero.security.core.property.Property;
import com.kero.security.core.role.Role;
import com.kero.security.core.scheme.proxy.AdaptiveProxyAgent;
import com.kero.security.core.scheme.proxy.CustomProxyAgent;
import com.kero.security.core.scheme.proxy.ProxyAgent;
import com.kero.security.core.scheme.proxy.SubclassProxyAgent;
import com.kero.security.core.utils.ByteBuddyClassUtils;

public class ClassAccessScheme implements AccessScheme, InvocationHandler {

	protected static Logger LOGGER = LoggerFactory.getLogger("Kero-Security");
	
	protected Class<?> type;
	protected String aliase;
	
	protected Access defaultAccess = Access.UNKNOWN;
	
	protected Map<String, Property> localProperties = new HashMap<>();
	
	protected KeroAccessAgent agent;
	
	protected boolean inherit = true;
	
	protected ProxyAgent proxyAgent = null;
	
	protected Map<Set<Role>, PreparedAccessConfiguration> configsCache = new HashMap<>();
	
	public ClassAccessScheme() {
	
	}
	
	public ClassAccessScheme(KeroAccessAgent agent, Class<?> type) {
		this();
		
		this.agent = agent;
		this.type = type;
		this.aliase = type.getSimpleName();
	}
	
	public ClassAccessScheme(KeroAccessAgent agent, String aliase, Class<?> type) {
		this(agent, type);
		
		this.aliase = aliase;
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

		Set<Property> properties = collectProperties();
		
		properties.forEach((property)-> {

			preparedActions.put(property.getName(), property.prepare(roles));
		});
		
		Access defaultAccess = determineDefaultAccess();
		
		PreparedAction defaultAction = null;
		
		if(defaultAccess == Access.GRANT) {
			
			defaultAction = new PreparedGrantRule(this, roles);
		}
		else if(defaultAccess == Access.DENY) {
			
			defaultAction = new PreparedDenyRule(this);
		}
		else if(defaultAccess == Access.UNKNOWN) {
			
			throw new RuntimeException("Can't prepare default access for : "+this+". Your Kero-Security configuration is bad, if you see this exception.");
		}
		
		return new PreparedAccessConfigurationImpl(this, preparedActions, defaultAction);
	}
	
	public Set<Property> collectProperties() {
	
		Map<String, Property> props = new HashMap<>();
		
		for(Property prop : getLocalProperties()) {
			
			props.put(prop.getName(), prop);
		}
		
		if(this.isInherit()) {
			
			Set<Property> parentProps = this.getParent().collectProperties();
			
			parentProps.forEach(prop -> props.putIfAbsent(prop.getName(), prop));
		}
		
		return new HashSet<>(props.values());
	}
	
	public Access determineDefaultAccess() {
		
		Access access = findDefaultAccess();
		
		if(access == Access.UNKNOWN) {
			
			access = agent.getDefaultAccess();
		}
		
		return access;
	}
	
	protected Access findDefaultAccess() {
		
		if(this.hasDefaultAccess()) return this.getDefaultAccess();
		
		if(!this.inherit) return Access.UNKNOWN;
		
		return getParent().determineDefaultAccess();
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
	
	@Override
	public Property createLocalProperty(String name) {
		
		LOGGER.debug("Creating property: "+name+" for scheme: "+this.getTypeClass().getSimpleName());
		
		Property prop = new Property(this, name);
		
		localProperties.put(name, prop);
		
		return prop;
	}

	@Override
	public boolean hasLocalProperty(String name) {
		
		return localProperties.containsKey(name);
	}

	@Override
	public Property getLocalProperty(String name) {
		
		return localProperties.get(name);
	}
	
	@Override
	public Set<Property> getLocalProperties() {
		
		return new HashSet<>(localProperties.values());
	}

	@Override
	public void setDefaultAccess(Access access) {
	
		this.defaultAccess = access;
	}

	@Override
	public boolean hasDefaultAccess() {
	
		return this.defaultAccess != Access.UNKNOWN;
	}

	@Override
	public Access getDefaultAccess() {
		
		return this.defaultAccess;
	}

	@Override
	public Class<?> getTypeClass() {
		
		return this.type;
	}
	
	@Override
	public KeroAccessAgent getAgent() {
		
		return this.agent;
	}
	
	@Override
	public String getAliase() {
		
		return this.aliase;
	}
	
	@Override
	public void setInherit(boolean i) {
		
		this.inherit = i;
	}
	
	@Override
	public boolean isInherit() {
		
		return this.inherit;
	}
}
