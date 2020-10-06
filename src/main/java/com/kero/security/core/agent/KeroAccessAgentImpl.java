package com.kero.security.core.agent;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.kero.security.core.access.annotations.Access;
import com.kero.security.core.configurator.KeroAccessConfigurator;
import com.kero.security.core.role.Role;
import com.kero.security.core.role.storage.RoleStorage;
import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.core.scheme.ClassAccessScheme;
import com.kero.security.core.scheme.configurator.AccessSchemeConfigurator;
import com.kero.security.core.scheme.definition.ClassAccessSchemeDefinition;
import com.kero.security.core.scheme.definition.configurator.AccessSchemeDefinitionConfigurator;
import com.kero.security.core.scheme.storage.AccessSchemeStorage;
import com.kero.security.core.scheme.strategy.AccessSchemeNamingStrategy;
import com.kero.security.core.scheme.strategy.DefaultAccessSchemeNamingStrategy;

public class KeroAccessAgentImpl implements KeroAccessAgent {
	
	protected static Logger LOGGER = LoggerFactory.getLogger("Kero-Security");
	
	protected RoleStorage roleStorage = RoleStorage.create();
	protected AccessSchemeStorage schemeStorage = AccessSchemeStorage.create();
	protected KeroAccessConfigurator configurator = new KeroAccessConfigurator(this);
		
	protected Access defaultAccess = Access.GRANT;
	
	protected ClassLoader proxiesClassLoader = ClassLoader.getSystemClassLoader();
	
	protected Set<Class> ignoreList = new HashSet<>();

	protected Map<Class, String> namesMap = new HashMap<>();

	protected Set<AccessSchemeConfigurator> configurators = new HashSet<>();
	protected Set<AccessSchemeDefinitionConfigurator> definitionConfigurators = new HashSet<>();
	
	protected AccessSchemeNamingStrategy schemeNamingStrategy = new DefaultAccessSchemeNamingStrategy();
	
	KeroAccessAgentImpl() {
		
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
	
	public void addConfigurator(AccessSchemeConfigurator configurator) {
		
		this.configurators.add(configurator);
	}
	
	public void addDefinitionConfigurator(AccessSchemeDefinitionConfigurator configurator) {
		
		this.definitionConfigurators.add(configurator);
	}
	
	public void setTypeName(String name, Class<?> type) {
		
		this.namesMap.put(type, name);
	}
	
	public void ignoreType(Class<?> type) {
		
		ignoreList.add(type);
	}
	
	@Override
	public boolean hasScheme(Class<?> rawType) {
		
		return schemeStorage.has(rawType);
	}

	@Override
	public AccessScheme getScheme(Class<?> rawType) {
		
		return schemeStorage.getOrDefault(rawType, AccessScheme.EMPTY);
	}
	
	@Override
	public AccessScheme getSchemeByName(String name) {
		
		return schemeStorage.getByName(name);
	}

	public AccessScheme getOrCreateScheme(Class<?> rawType){
		
		return hasScheme(rawType) ? getScheme(rawType) : createScheme(rawType);
	}
	
	public AccessScheme createScheme(Class<?> rawType) {
		
		if(rawType == null) return AccessScheme.EMPTY;	
		if(rawType.isInterface()) throw new RuntimeException("Can't create scheme for interface!");
		
		String name = schemeNamingStrategy.getName(rawType);
		
			if(namesMap.containsKey(rawType)) {
				
				name = namesMap.get(rawType);
			}
		
		ClassAccessSchemeDefinition definition = new ClassAccessSchemeDefinition(this, name, rawType);
			
			for(AccessSchemeDefinitionConfigurator configurator : definitionConfigurators) {
				
				configurator.configure(definition);
			}
		
		LOGGER.debug("Creating access scheme for class: "+rawType.getCanonicalName());
		
		AccessScheme scheme = definition.createScheme();

			for(AccessSchemeConfigurator configurator : configurators) {
				
				configurator.configure(scheme);
			}
		
		schemeStorage.add(scheme);
		
		return scheme;
	}

	@Override
	public <T> T protect(T object, Collection<Role> roles) {
		
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
	
	public String extractPropertyName(String rawName) {
		
		if(rawName.startsWith("get")) {
			
			rawName = rawName.replaceFirst("get", "");
		}
		
		rawName = rawName.toLowerCase();
	
		return rawName;
	}
	
	@Override
	public Access getDefaultAccess() {
		
		return this.defaultAccess;
	}

	@Override
	public ClassLoader getClassLoader() {
		
		return this.proxiesClassLoader;
	}
	
	@Override
	public KeroAccessConfigurator getKeroAccessConfigurator() {
		
		return this.configurator;
	}

	@Override
	public Role createRole(String name) {
		
		return this.roleStorage.create(name);
	}

	@Override
	public Role getRole(String name) {
		
		return this.roleStorage.get(name);
	}

	@Override
	public Role hasRole(String name) {
		
		return this.roleStorage.create(name);
	}

	@Override
	public Role getOrCreateRole(String name) {
		
		return this.roleStorage.getOrCreate(name);
	}

	@Override
	public Set<Role> getOrCreateRole(Collection<String> names) {
		
		return this.roleStorage.getOrCreate(names);
	}

	@Override
	public Set<Role> getOrCreateRole(String[] names) {
		
		return this.roleStorage.getOrCreate(names);
	}

	@Override
	public RoleStorage getRoleStorage() {
		
		return this.roleStorage;
	}

	@Override
	public AccessSchemeStorage getSchemeStorage() {
		
		return this.schemeStorage;
	}
}
