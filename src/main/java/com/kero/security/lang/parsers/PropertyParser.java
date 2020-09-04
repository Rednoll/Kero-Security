package com.kero.security.lang.parsers;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Queue;
import java.util.Set;

import com.kero.security.lang.nodes.AccessRuleNode;
import com.kero.security.lang.nodes.DefaultRuleNode;
import com.kero.security.lang.nodes.PropertyMetalineBase;
import com.kero.security.lang.nodes.PropertyNode;
import com.kero.security.lang.parsers.metaline.HasMetalines;
import com.kero.security.lang.parsers.metaline.MetalineParser;
import com.kero.security.lang.tokens.DefaultRuleToken;
import com.kero.security.lang.tokens.KsdlToken;
import com.kero.security.lang.tokens.NameToken;
import com.kero.security.lang.tokens.RoleToken;

public class PropertyParser extends KsdlNodeParserBase<PropertyNode> implements HasBlock<RoleToken>, HasMetalines<PropertyMetalineBase> {

	private List<MetalineParser<? extends PropertyMetalineBase>> metalineParsers = new ArrayList<>();
	
	public PropertyParser() {
	
		metalineParsers.add(new PropagationParser());
	}
	
	public PropertyNode parse(Queue<KsdlToken> tokens) {
		
		NameToken nameToken = (NameToken) tokens.poll();
		
		DefaultRuleToken defaultRuleToken = DefaultRuleToken.EMPTY;
		
		if(tokens.peek() instanceof DefaultRuleToken) {
			
			defaultRuleToken = (DefaultRuleToken) tokens.poll();
		}
		
		Set<String> grantRoles = new HashSet<>();
		Set<String> denyRoles = new HashSet<>();
		
		List<RoleToken> roles = this.parseBlock(tokens);
		
		for(RoleToken role : roles) {
			
			if(role.getAccessible()) {
				
				grantRoles.add(role.getRoleName());
			}
			else {
				
				denyRoles.add(role.getRoleName());
			}
		}
		
		List<PropertyMetalineBase> metalines = this.parseMetalines(tokens);
		
		String name = nameToken.getRaw();
		
		DefaultRuleNode defaultRule = defaultRuleToken.toNode();
		
		AccessRuleNode grantRule = new AccessRuleNode(grantRoles, true);
		AccessRuleNode denyRule = new AccessRuleNode(denyRoles, false);
		
		return new PropertyNode(name, defaultRule, grantRule, denyRule, metalines);
	}

	@Override
	public List<MetalineParser<? extends PropertyMetalineBase>> getMetalineParsers() {
		
		return metalineParsers;
	}
	
	@Override
	public RoleToken parseBlockUnit(Queue<KsdlToken> tokens) {
		
		return (RoleToken) tokens.poll();
	}
}
