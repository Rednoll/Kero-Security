package com.kero.security.core;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.kero.security.core.role.Role;
import com.kero.security.core.role.storage.RoleStorage;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.rules.AccessRuleImpl;
import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.core.scheme.ClassAccessScheme;
import com.kero.security.core.scheme.InterfaceAccessScheme;
import com.kero.security.core.scheme.configuration.KeroAccessConfigurator;
import com.kero.security.core.scheme.configuration.auto.AccessSchemeAutoConfigurator;

public class KeroAccessManagerImpl implements KeroAccessManager {
	
	protected static Logger LOGGER = LoggerFactory.getLogger("KeroSecurity");
	
	protected Map<Class, AccessScheme> schemes = new HashMap<>();
	
	protected RoleStorage roleStorage = RoleStorage.create();
	
	protected AccessRule defaultRule = AccessRuleImpl.GRANT_ALL;
	
	protected ClassLoader proxiesClassLoader = ClassLoader.getSystemClassLoader();
	
	protected Set<Class> ignoreList = new HashSet<>();
	
	protected String basePackage = "com.kero";
	protected boolean scaned = false;
	
	protected Map<Class, String> aliasesMap = new HashMap<>();
	
	protected KeroAccessConfigurator configurator = new KeroAccessConfigurator(this);
	
	protected Set<AccessSchemeAutoConfigurator> autoConfigurators = new HashSet<>();
	
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
	
	public void addConfigurator(AccessSchemeAutoConfigurator configurator) {
		
		this.autoConfigurators.add(configurator);
	}
	
	public void setTypeAliase(String aliase, Class<?> type) {
		
		this.aliasesMap.put(type, aliase);
	}
	
	public void setBasePackage(String basePackage) {
		
		this.basePackage = basePackage;
	}
	
	public void ignoreType(Class<?> type) {
		
		ignoreList.add(type);
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
	public AccessScheme getSchemeByAlise(String aliase) {
		
		for(AccessScheme scheme : schemes.values()) {
			
			if(scheme.getAliase().equals(aliase)) {
				
				return scheme;
			}
		}
		
		return null;
	}

	public AccessScheme getOrCreateScheme(Class<?> rawType){
		
		return hasScheme(rawType) ? getScheme(rawType) : createScheme(rawType);
	}
	
	public AccessScheme createScheme(Class<?> rawType) {
		
		AccessScheme scheme = null;
		
		String aliase = rawType.getSimpleName();
		
		if(aliasesMap.containsKey(rawType)) {
			
			aliase = aliasesMap.get(rawType);
		}
		
		if(rawType.isInterface()) {
			
			LOGGER.debug("Creating access scheme for interface: "+rawType.getCanonicalName());
			scheme = new InterfaceAccessScheme(this, aliase, rawType);
		}
		else {
			
			LOGGER.debug("Creating access scheme for class: "+rawType.getCanonicalName());
			scheme = new ClassAccessScheme(this, aliase, rawType);
		}
		
		for(AccessSchemeAutoConfigurator ac : autoConfigurators) {
			
			ac.configure(scheme);
		}
		
		schemes.put(rawType, scheme);
		
		return scheme;
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
	
	@Override
	public AccessRule getDefaultRule() {
		
		return this.defaultRule;
	}

	@Override
	public ClassLoader getClassLoader() {
		
		return this.proxiesClassLoader;
	}
	
	@Override
	public KeroAccessConfigurator getConfigurator() {
		
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
}
