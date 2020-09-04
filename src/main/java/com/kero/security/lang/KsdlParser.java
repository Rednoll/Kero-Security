package com.kero.security.lang;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import com.kero.security.lang.nodes.KsdlRootNode;
import com.kero.security.lang.parsers.KsdlRootNodeParser;
import com.kero.security.lang.parsers.SchemeParser;
import com.kero.security.lang.tokens.KsdlToken;

public class KsdlParser {

	protected List<KsdlRootNodeParser<? extends KsdlRootNode>> parsers;
	
	public KsdlParser() {
		
		this.parsers = new ArrayList<>();
			parsers.add(new SchemeParser());
	}
	
	public List<KsdlRootNode> parse(List<KsdlToken> tokens) {
		
		LinkedList<KsdlToken> tokensQueue = new LinkedList<>(tokens);
		
		List<KsdlRootNode> roots = new ArrayList<>();
		
		c2: while(!tokensQueue.isEmpty()) {
			
			for(KsdlRootNodeParser<? extends KsdlRootNode> parser : this.parsers) {
				
				if(parser.isMatch(tokensQueue)) {
					
					KsdlRootNode node = parser.parse(tokensQueue);
				
					System.out.println("Node: "+node);
					
					roots.add(node);
					
					continue c2;
				}
			}
		}
		
		return roots;
	}
}
