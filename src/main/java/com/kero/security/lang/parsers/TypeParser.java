package com.kero.security.lang.parsers;

import java.util.HashSet;
import java.util.List;
import java.util.Queue;
import java.util.Set;

import com.kero.security.lang.nodes.PropertyNode;
import com.kero.security.lang.nodes.TypeNode;
import com.kero.security.lang.tokens.DefaultRuleToken;
import com.kero.security.lang.tokens.KeyWordToken;
import com.kero.security.lang.tokens.KsdlToken;
import com.kero.security.lang.tokens.NameToken;

public class TypeParser extends KsdlNodeParserBase<TypeNode> implements KsdlRootNodeParser<TypeNode> {

	private PropertyParser propertyParser = new PropertyParser();
	
	public boolean isMatch(List<KsdlToken> tokens) {
		
		if(tokens.get(0) != KeyWordToken.SCHEME) return false;
		if(!(tokens.get(1) instanceof NameToken)) return false;
		
		return true;
	}
	
	public TypeNode parse(Queue<KsdlToken> tokens) {
	
		tokens.poll(); //PROTECT
		
		NameToken nameToken = (NameToken) tokens.poll();
		
		DefaultRuleToken defaultRuleToken = null;
		
		if(tokens.peek() instanceof DefaultRuleToken) {
			
			defaultRuleToken = (DefaultRuleToken) tokens.poll();
		}
		
		Set<PropertyNode> props = new HashSet<>();
		
		if(tokens.peek() == KeyWordToken.OPEN_BLOCK) {

			tokens.poll();
			
			int lastSize = -1;
			
			while(!tokens.isEmpty()) {
				
				if(tokens.peek() instanceof NameToken) {
					
					PropertyNode prop = propertyParser.parse(tokens);
				
					props.add(prop);
				}
				else if(tokens.peek() == KeyWordToken.CLOSE_BLOCK) {
				
					tokens.poll();
					
					break;
				}
				
				if(lastSize == tokens.size()) {
					
					throw new RuntimeException("Can't parse!");
				}
				
				lastSize = tokens.size();
			}
		}
		
		String typeName = nameToken.getRaw();
		Boolean defaultRule = defaultRuleToken != null ? defaultRuleToken.getDefaultAccessible() : null;
		
		return new TypeNode(typeName, defaultRule, props);
	}
}
