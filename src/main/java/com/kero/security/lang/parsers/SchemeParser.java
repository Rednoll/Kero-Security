package com.kero.security.lang.parsers;

import java.util.List;

import com.kero.security.lang.collections.TokenSequence;
import com.kero.security.lang.nodes.DefaultAccessNode;
import com.kero.security.lang.nodes.PropertyNode;
import com.kero.security.lang.nodes.SchemeNode;
import com.kero.security.lang.tokens.DefaultAccessToken;
import com.kero.security.lang.tokens.KeyWordToken;
import com.kero.security.lang.tokens.NameToken;

public class SchemeParser extends KsdlNodeParserBase<SchemeNode> implements KsdlRootNodeParser<SchemeNode>, HasBlock<PropertyNode> {

	private PropertyParser propertyParser = new PropertyParser();
	
	public boolean isMatch(TokenSequence tokens) {
		
		if(!tokens.isToken(0, KeyWordToken.SCHEME)) return false;
		if(!tokens.isToken(1, NameToken.class)) return false;
		
		return true;
	}
	
	public SchemeNode parse(TokenSequence tokens) {
	
		tokens.poll(); //SCHEME
		
		NameToken nameToken = (NameToken) tokens.poll();
		
		DefaultAccessToken defaultRuleToken = tokens.tryGetOrDefault(DefaultAccessToken.EMPTY);
		
		List<PropertyNode> props = this.parseBlock(tokens);
		String typeName = nameToken.getRaw();
		DefaultAccessNode defaultRule = defaultRuleToken.toNode();
		
		return new SchemeNode(typeName, defaultRule, props);
	}

	@Override
	public PropertyNode parseBlockUnit(TokenSequence tokens) {
		
		return propertyParser.parse(tokens);
	}
}
