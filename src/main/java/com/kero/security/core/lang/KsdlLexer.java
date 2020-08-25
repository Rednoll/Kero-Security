package com.kero.security.core.lang;

import java.util.LinkedList;
import java.util.List;

import com.kero.security.core.lang.lexems.KsdlLexem;
import com.kero.security.core.lang.lexems.PropertyLexem;
import com.kero.security.core.lang.lexems.RoleLexem;
import com.kero.security.core.lang.lexems.TypeLexem;
import com.kero.security.core.lang.tokens.KsdlToken;

public class KsdlLexer {

	private List<KsdlLexem> lexems = new LinkedList<>();
	
	public KsdlLexer() {
		
		lexems.add(new PropertyLexem());
		lexems.add(new RoleLexem());
		lexems.add(new TypeLexem());
	}
	
	public List<KsdlToken> tokenize(String data) {
		
		data = data.replaceAll("\n", " ");
		data = data.replaceAll("	", " ");
		data = data.replaceAll(" +", " ");
		
		List<KsdlToken> tokens = new LinkedList<>();
		
		c2: while(data.isEmpty()) {
			
			for(KsdlLexem lexem : lexems) {
				
				String lexemaPattern = lexem.getPattern();
				
				String newData = data.replaceFirst(lexemaPattern, "");
				
				String rawToken = data.substring(0, data.length() - newData.length());
				
				if(!data.startsWith(rawToken)) continue;
				
				tokens.add(lexem.tokenize(rawToken));
				
				continue c2;
			}
			
			throw new RuntimeException("Lexem not found!");
		}
		
		return tokens;
	}
}
