package com.kero.security.lang.parsers;

import java.util.List;
import java.util.Queue;

import com.kero.security.lang.nodes.DefaultRuleNode;
import com.kero.security.lang.nodes.PropertyNode;
import com.kero.security.lang.nodes.SchemeNode;
import com.kero.security.lang.tokens.DefaultRuleToken;
import com.kero.security.lang.tokens.KeyWordToken;
import com.kero.security.lang.tokens.KsdlToken;
import com.kero.security.lang.tokens.NameToken;

public class SchemeParser extends KsdlNodeParserBase<SchemeNode> implements KsdlRootNodeParser<SchemeNode>, HasBlock<PropertyNode> {

	private PropertyParser propertyParser = new PropertyParser();
	
	public boolean isMatch(List<KsdlToken> tokens) {
		
		if(tokens.get(0) != KeyWordToken.SCHEME) return false;
		if(!(tokens.get(1) instanceof NameToken)) return false;
		
		return true;
	}
	
	public SchemeNode parse(Queue<KsdlToken> tokens) {
	
		tokens.poll(); //SCHEME
		
		NameToken nameToken = (NameToken) tokens.poll();
		
		DefaultRuleToken defaultRuleToken = DefaultRuleToken.EMPTY;
		
		if(tokens.peek() instanceof DefaultRuleToken) {
			
			defaultRuleToken = (DefaultRuleToken) tokens.poll();
		}
		
		List<PropertyNode> props = this.parseBlock(tokens);
		String typeName = nameToken.getRaw();
		DefaultRuleNode defaultRule = defaultRuleToken.toNode();
		
		return new SchemeNode(typeName, defaultRule, props);
	}

	@Override
	public PropertyNode parseBlockUnit(Queue<KsdlToken> tokens) {
		
		return propertyParser.parse(tokens);
	}
}
