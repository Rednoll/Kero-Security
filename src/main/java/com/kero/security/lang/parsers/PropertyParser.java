package com.kero.security.lang.parsers;

import java.util.HashSet;
import java.util.Queue;
import java.util.Set;

import com.kero.security.core.role.Role;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.rules.AccessRuleImpl;
import com.kero.security.lang.nodes.PropertyNode;
import com.kero.security.lang.tokens.DefaultRuleToken;
import com.kero.security.lang.tokens.KeyWordToken;
import com.kero.security.lang.tokens.KsdlToken;
import com.kero.security.lang.tokens.NameToken;
import com.kero.security.lang.tokens.RoleToken;
import com.kero.security.managers.KeroAccessManager;

public class PropertyParser extends KsdlNodeParserBase<PropertyNode> {

	public PropertyNode parse(Queue<KsdlToken> tokens) {
		
		NameToken nameToken = (NameToken) tokens.poll();
		
		DefaultRuleToken defaultRuleToken = null;
		
		if(tokens.peek() instanceof DefaultRuleToken) {
			
			defaultRuleToken = (DefaultRuleToken) tokens.poll();
		}
		
		String name = nameToken.getRaw();
		Boolean defaultRule = defaultRuleToken != null ? defaultRuleToken.getDefaultAccessible() : null;
			
		if(tokens.peek() == KeyWordToken.OPEN_BLOCK) {
			
			tokens.poll();
			
			Set<String> grantRoles = new HashSet<>();
			Set<String> denyRoles = new HashSet<>();
			
			while(!tokens.isEmpty()) {
				
				if(tokens.peek() instanceof RoleToken) {
					
					RoleToken roleToken = (RoleToken) tokens.poll();
				
					if(roleToken.getAccessible()) {
						
						grantRoles.add(roleToken.getRoleName());
					}
					else {
						
						denyRoles.add(roleToken.getRoleName());
					}
				}
				else if(tokens.peek() == KeyWordToken.CLOSE_BLOCK){
					
					tokens.poll();
					
					break;
				}
			}
			
			return new PropertyNode(name, defaultRule, grantRoles, grantRoles);	
		}
		else {
			
			return new PropertyNode(name, defaultRule, null, null);
		}
	}
}
