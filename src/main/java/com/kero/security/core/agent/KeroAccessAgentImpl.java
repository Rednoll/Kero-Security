package com.kero.security.core.agent;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.kero.security.core.access.Access;
import com.kero.security.core.agent.exception.AccessSchemeIncorrectTypeException;
import com.kero.security.core.configurator.KeroAccessConfigurator;
import com.kero.security.core.protector.KeroProtector;
import com.kero.security.core.protector.storage.KeroProtectorStorage;
import com.kero.security.core.role.Role;
import com.kero.security.core.role.storage.RoleStorage;
import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.core.scheme.ClassAccessScheme;
import com.kero.security.core.scheme.configurator.AccessSchemeConfigurator;
import com.kero.security.core.scheme.configurator.KsdlAccessSchemeConfigurator;
import com.kero.security.core.scheme.definition.ClassAccessSchemeDefinition;
import com.kero.security.core.scheme.definition.configurator.AccessSchemeDefinitionConfigurator;
import com.kero.security.core.scheme.storage.AccessSchemeStorage;
import com.kero.security.core.scheme.strategy.AccessSchemeNamingStrategy;
import com.kero.security.core.scheme.strategy.DefaultAccessSchemeNamingStrategy;
import com.kero.security.lang.provider.BaseCompositeProvider;
import com.kero.security.lang.provider.CompositeProvider;
import com.kero.security.lang.provider.KsdlProvider;

public class KeroAccessAgentImpl implements KeroAccessAgent {
	
	protected static Logger LOGGER = LoggerFactory.getLogger("Kero-Security");
	
	protected RoleStorage roleStorage = RoleStorage.create();
	protected AccessSchemeStorage schemeStorage = AccessSchemeStorage.create();
	protected KeroProtectorStorage protectorStorage = KeroProtectorStorage.create();
	protected KeroAccessConfigurator configurator = new KeroAccessConfigurator(this);
		
	protected Access defaultAccess = Access.GRANT;
	
	protected Set<Class> ignoreList = new HashSet<>();

	protected Map<Class, String> namesMap = new HashMap<>();

	protected Set<AccessSchemeConfigurator> configurators = new HashSet<>();
	protected Set<AccessSchemeDefinitionConfigurator> definitionConfigurators = new HashSet<>();
	
	protected AccessSchemeNamingStrategy schemeNamingStrategy = new DefaultAccessSchemeNamingStrategy();
	
	protected CompositeProvider mainKsdlProvider;
	
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
		
		this.mainKsdlProvider = new BaseCompositeProvider();
		
		this.addConfigurator(new KsdlAccessSchemeConfigurator(this.mainKsdlProvider));
	}
	
	public void preloadMainProvider() {
		
		this.mainKsdlProvider.preloadResource();
	}
	
	public void addKsdlProvider(KsdlProvider provider) {
		
		this.mainKsdlProvider.addProvider(provider);
	}
	
	public void setMainProvider(CompositeProvider provider) {
		
		this.mainKsdlProvider = provider;
	}
	
	public CompositeProvider getMainProvider() {
		
		return this.mainKsdlProvider;
	}
	
	public void setSchemeNamingStrategy(AccessSchemeNamingStrategy strategy) {
	
		this.schemeNamingStrategy = strategy;
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
		if(rawType.isInterface()) throw new AccessSchemeIncorrectTypeException("Can't create scheme for interface!");
		
		String name = schemeNamingStrategy.getName(rawType);
		
			if(namesMap.containsKey(rawType)) {
				
				name = namesMap.get(rawType);
			}
		
		LOGGER.debug("Creating access scheme for class: "+rawType.getCanonicalName());	
			
		ClassAccessSchemeDefinition definition = new ClassAccessSchemeDefinition(this, name, rawType);
			
			for(AccessSchemeDefinitionConfigurator configurator : definitionConfigurators) {
				
				configurator.configure(definition);
			}
		
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
		if(object instanceof Enum) return object;
		if(this.ignoreList.contains(object.getClass())) return object;
		
		ClassAccessScheme scheme = (ClassAccessScheme) getOrCreateScheme(object.getClass());
		KeroProtector protector = protectorStorage.getOrCreateProtector(scheme);
		
		return protector.protect(object, roles);
	}
	
	public String extractPropertyName(String rawName) {
		
		String name = rawName;
		
		if(name.startsWith("get")) {
			
			name = name.replaceFirst("get", "");
		}
		
		name = name.toLowerCase();
	
		return name;
	}
	
	@Override
	public Access getDefaultAccess() {
		
		return this.defaultAccess;
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
