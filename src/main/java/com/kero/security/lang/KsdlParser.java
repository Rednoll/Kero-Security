package com.kero.security.lang;

import java.util.ArrayList;
import java.util.List;

import com.kero.security.lang.collections.RootNodeList;
import com.kero.security.lang.collections.TokenSequence;
import com.kero.security.lang.nodes.KsdlRootNode;
import com.kero.security.lang.parsers.KsdlRootNodeParser;
import com.kero.security.lang.parsers.SchemeParser;

public class KsdlParser {

	protected List<KsdlRootNodeParser<? extends KsdlRootNode>> parsers;
	
	public KsdlParser() {
		
		this.parsers = new ArrayList<>();
			parsers.add(new SchemeParser());
	}
	
	public RootNodeList parse(TokenSequence tokensArg) {
		
		TokenSequence tokens = new TokenSequence(tokensArg);
		
		RootNodeList roots = new RootNodeList();
		
		c2: while(!tokens.isEmpty()) {
			
			for(KsdlRootNodeParser<? extends KsdlRootNode> parser : this.parsers) {
				
				if(parser.isMatch(tokens)) {
					
					KsdlRootNode node = parser.parse(tokens);
					
					roots.add(node);
					
					continue c2;
				}
			}
		}
		
		return roots;
	}
}
