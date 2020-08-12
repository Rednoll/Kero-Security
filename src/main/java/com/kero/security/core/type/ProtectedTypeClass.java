package com.kero.security.core.type;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.kero.security.core.config.PreparedAccessConfiguration;
import com.kero.security.core.config.PreparedAccessConfigurationImpl;
import com.kero.security.core.config.PreparedDenyRule;
import com.kero.security.core.config.PreparedGrantRule;
import com.kero.security.core.config.PreparedRule;
import com.kero.security.core.managers.KeroAccessManager;
import com.kero.security.core.property.Property;
import com.kero.security.core.role.Role;
import com.kero.security.core.rules.AccessRule;

import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.modifier.Visibility;
import net.bytebuddy.implementation.FieldAccessor;
import net.bytebuddy.implementation.InvocationHandlerAdapter;
import net.bytebuddy.implementation.MethodCall;
import net.bytebuddy.matcher.ElementMatchers;

public class ProtectedTypeClass extends ProtectedTypeBase implements InvocationHandler {

	private static Logger LOGGER = LoggerFactory.getLogger("KeroSecurity");
	
	private Class<?> proxyClass = null;
	
	private Field originalField = null;
	private Field pacField = null;
	
	private Map<String, Property> cashedRules;
	
	private Map<Set<Role>, PreparedAccessConfiguration> configsCache = new HashMap<>();
	
	public ProtectedTypeClass() {
		super();
	
	}
	
	public ProtectedTypeClass(KeroAccessManager manager, Class<?> type, AccessRule defaultRule) throws Exception {
		super(manager, type, defaultRule);
	
		this.proxyClass = new ByteBuddy()
				.subclass(type)
				.defineField("original", type, Visibility.PRIVATE)
				.defineField("pac", PreparedAccessConfiguration.class, Visibility.PRIVATE)
				.defineConstructor(Visibility.PUBLIC)
				.withParameters(type, PreparedAccessConfiguration.class)
				.intercept(MethodCall.invoke(type.getConstructor()).andThen(FieldAccessor.ofField("original").setsArgumentAt(0).andThen(FieldAccessor.ofField("pac").setsArgumentAt(1))))
				.method(ElementMatchers.isPublic())
				.intercept(InvocationHandlerAdapter.of(this))
				.make()
				.load(ClassLoader.getSystemClassLoader())
				.getLoaded();
		
		this.originalField = this.proxyClass.getDeclaredField("original");
		this.originalField.setAccessible(true);
 
		this.pacField = this.proxyClass.getDeclaredField("pac");
		this.pacField.setAccessible(true);
	}
	
	public void updateRules() {
		
		this.cashedRules = collectRules();
	}

	@Override
	public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
		
		Object original = originalField.get(proxy);
		PreparedAccessConfiguration pac = (PreparedAccessConfiguration) pacField.get(proxy);
	
		return pac.process(original, method, args);
	}
	
	public <T> T protect(T object, Set<Role> roles) throws Exception {
		
		PreparedAccessConfiguration config = configsCache.get(roles);
		
		if(config == null) {
	
			config = prepareAccessConfiguration(roles);
			configsCache.put(roles, config);
		}
		
		return (T) proxyClass.getConstructor(this.type, PreparedAccessConfiguration.class).newInstance(object, config);	
	}
	
	private PreparedAccessConfiguration prepareAccessConfiguration(Set<Role> roles) {
		
		String rolesList = "[";
		
		for(Role role : roles) {
			
			rolesList += role.getName()+" ";
		}
		
		rolesList = rolesList.trim()+"]";
		
		LOGGER.debug("Prepare access configuration for "+type.getCanonicalName()+" roles: "+rolesList);
		
		Map<String, PreparedRule> preparedRules = new HashMap<>();

		updateRules();
		
		cashedRules.forEach((propertyName, property)-> {
			
			Set<Role> significantRoles = new HashSet<>(roles);
			
			List<AccessRule> rules = property.getRules();
			 
			for(AccessRule rule : rules) {
 
				if(!rule.manage(significantRoles)) continue;
 
				if(rule.accessible(significantRoles)) {
 
					preparedRules.put(propertyName, new PreparedGrantRule());
					return;
				}
				else if(rule.isDisallower()) {
 
					significantRoles.removeAll(rule.getRoles());
				}
			}
			
			//REWRITE SILENT INTECEPTOR PICKER / IT'S STUB!
			for(AccessRule rule : property.getRules()) {
				
				if(rule.manage(roles) && rule.hasSilentInterceptor()) {
					
					preparedRules.put(propertyName, rule.prepare(roles));
					return;
				}
			}
			//
			
			if(significantRoles.isEmpty()) {
			
				preparedRules.put(propertyName, new PreparedDenyRule());
				return;
			}

			if(property.hasDefaultRule()) {
			
				preparedRules.put(propertyName, property.getDefaultRule().prepare(roles));
				return;
			}
			else {
				
				ProtectedType propertyOwner = property.getOwner();
				
				preparedRules.put(propertyName, propertyOwner.getDefaultRule().prepare(roles));
				return;
			}
		});
		
		PreparedRule defaultTypeRule = findDefaultRule().prepare(roles);
		
		return new PreparedAccessConfigurationImpl(preparedRules, defaultTypeRule);
	}
	
	private AccessRule findDefaultRule() {
		
		if(this.hasDefaultRule()) return this.getDefaultRule();

		Class<?> superClass = this.type.getSuperclass();
		
		while(superClass != Object.class) {
			
			if(manager.hasType(superClass)) {
				
				ProtectedType type = manager.getType(superClass);
			
				if(type.hasDefaultRule()) {
					
					return type.getDefaultRule();
				}
			}
			
			superClass = superClass.getSuperclass();
		}
		
		return manager.getDefaultRule();
	}
	
	public void collectRules(Map<String, Property> complexProperties, Map<String, Set<Role>> processedRoles) {
		
		collectLocalRules(complexProperties, processedRoles);
		collectFromInterfaces(complexProperties, processedRoles);
		collectFromSuperclass(complexProperties, processedRoles);
	}
	
	protected void collectFromSuperclass(Map<String, Property> complexProperties, Map<String, Set<Role>> processedRoles) {
		
		Class<?> superclass = type.getSuperclass();
		
		while(superclass != Object.class) {
			
			ProtectedType supeclassType = manager.getOrCreateType(superclass);

			supeclassType.collectRules(complexProperties, processedRoles);

			superclass = superclass.getSuperclass();
		}
	}
}
