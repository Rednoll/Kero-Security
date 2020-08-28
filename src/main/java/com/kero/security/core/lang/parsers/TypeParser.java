package com.kero.security.core.lang.parsers;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.kero.security.core.lang.KsdlLexer;
import com.kero.security.core.lang.nodes.PropertyNode;
import com.kero.security.core.lang.nodes.TypeNode;
import com.kero.security.core.lang.tokens.DefaultRuleToken;
import com.kero.security.core.lang.tokens.KsdlToken;
import com.kero.security.core.lang.tokens.NameToken;
import com.kero.security.core.managers.KeroAccessManager;
import com.kero.security.core.rules.AccessRule;

public class TypeParser extends KsdlNodeParserBase {

	public boolean isHeaderMatch(List<KsdlToken> tokens) {
		
		if(tokens.get(0) != KsdlLexer.WORD_PROTECT) return false;
		if(NameToken.class.isAssignableFrom(tokens.get(1).getClass())) return false;
		
		return true;
	}
	
	public TypeNode parse(KeroAccessManager manager, List<KsdlToken> tokens) {
		
		int iterator = 1; // 0 - PROTECT
		
		NameToken nameToken = (NameToken) tokens.get(iterator);
		iterator++;
		
		DefaultRuleToken defaultRuleToken = null;
		
		if(tokens.get(iterator) instanceof DefaultRuleToken) {
			
			defaultRuleToken = (DefaultRuleToken) tokens.get(iterator);
			iterator++;
		}
		
		Set<PropertyNode> props = new HashSet<>();

		if(tokens.get(iterator) == KsdlLexer.WORD_METABLOCK) {
			
			iterator++;

			while(iterator < tokens.size()) {
				
				if(tokens.get(iterator) instanceof NameToken) {
					
					PropertyNode prop = new PropertyParser().parse(manager, tokens.subList(iterator, tokens.size()));
				
					props.add(prop);
				}
				
				iterator++;
			}
		}
		
		Class<?> type = manager.getTypeByAliase(nameToken.getRaw());
		AccessRule defaultRule = defaultRuleToken.getDefaultAccessible() ? AccessRule.GRANT_ALL : AccessRule.DENY_ALL;
		
		//TODO: TYPE DETERMINATION
		return new TypeNode(type, defaultRule, props);
	}
}
