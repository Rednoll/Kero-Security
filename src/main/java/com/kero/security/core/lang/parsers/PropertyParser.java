package com.kero.security.core.lang.parsers;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.kero.security.core.lang.KsdlLexer;
import com.kero.security.core.lang.nodes.PropertyNode;
import com.kero.security.core.lang.tokens.DefaultRuleToken;
import com.kero.security.core.lang.tokens.KsdlToken;
import com.kero.security.core.lang.tokens.NameToken;
import com.kero.security.core.lang.tokens.RoleToken;
import com.kero.security.core.managers.KeroAccessManager;
import com.kero.security.core.role.Role;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.rules.AccessRuleImpl;

public class PropertyParser {

	public PropertyNode parse(KeroAccessManager manager, List<KsdlToken> tokens) {
		
		int iterator = 0;
		
		NameToken nameToken = (NameToken) tokens.get(iterator);
		iterator++;
		
		DefaultRuleToken defaultRuleToken = null;
		
		if(tokens.get(iterator) instanceof DefaultRuleToken) {
			
			defaultRuleToken = (DefaultRuleToken) tokens.get(iterator);
			iterator++;
		}
		
		String name = nameToken.getRaw();
		AccessRule defaultRule = null;
		
			if(defaultRuleToken != null) {
				defaultRule = defaultRuleToken.getDefaultAccessible() ? AccessRule.GRANT_ALL : AccessRule.DENY_ALL;
			}
			
		if(tokens.get(iterator) == KsdlLexer.WORD_METABLOCK) {
			
			iterator++;
			
			Set<Role> grantRoles = new HashSet<>();
			Set<Role> denyRoles = new HashSet<>();
			
			while(iterator < tokens.size()) {
				
				if(tokens.get(iterator) instanceof RoleToken) {
					
					RoleToken roleToken = (RoleToken) tokens.get(iterator);
				
					if(roleToken.getAccessible()) {
						
						grantRoles.add(manager.getOrCreateRole(roleToken.getRoleName()));
					}
					else {
						
						denyRoles.add(manager.getOrCreateRole(roleToken.getRoleName()));
					}
					
					iterator++;
				}
				else {
					
					break;
				}
			}
			
			AccessRule grantRule = new AccessRuleImpl(grantRoles, true);
			AccessRule denyRule = new AccessRuleImpl(denyRoles, true);
			
			return new PropertyNode(name, defaultRule, grantRule, denyRule);	
		}
		else {
			
			return new PropertyNode(name, defaultRule, null, null);
		}
	}
}
