package com.kero.security.core.lang;

import java.util.LinkedList;
import java.util.List;

import com.kero.security.core.lang.lexems.DefaultRuleLexem;
import com.kero.security.core.lang.lexems.KeyWordLexem;
import com.kero.security.core.lang.lexems.KsdlLexem;
import com.kero.security.core.lang.lexems.NameLexem;
import com.kero.security.core.lang.lexems.RoleLexem;
import com.kero.security.core.lang.tokens.KsdlToken;

public class KsdlLexer {

	public static KeyWordLexem WORD_PROTECT = new KeyWordLexem("protect");
	public static KeyWordLexem WORD_METABLOCK = new KeyWordLexem(":");
	
	private List<KeyWordLexem> keyWords = new LinkedList<>();
	private List<KsdlLexem> lexems = new LinkedList<>();
	
	public KsdlLexer() {
	
		keyWords.add(WORD_PROTECT);
		keyWords.add(WORD_METABLOCK);
		
		lexems.add(new DefaultRuleLexem());
		lexems.add(new RoleLexem());
		lexems.add(new NameLexem());
	}
	
	public List<KsdlToken> tokenize(String data) {
		
		data = data.replaceAll("\n", " ");
		data = data.replaceAll("	", " ");
		data = data.replaceAll(" +", " ");
		
		List<KsdlToken> tokens = new LinkedList<>();

		StringBuilder currentRawToken = new StringBuilder();

		c2: for(char ch : data.toCharArray()) {
			
			boolean found = checkWord(tokens, currentRawToken, ch);
			
			if(found) {
				
				if(ch != ' ')
				currentRawToken.append(ch);
				continue c2;
			}
			
			checkLexem(tokens, currentRawToken, ch);

			if(ch != ' ')
			currentRawToken.append(ch);
		}
		
		checkLexem(tokens, currentRawToken, '\0');
		
		return tokens;
	}
	
	private boolean checkLexem(List<KsdlToken> tokens, StringBuilder currentRawToken, char ch) {
		
		for(KsdlLexem lexem : lexems) {
			
			if(lexem.isMatch(currentRawToken) && !lexem.isMatch(currentRawToken.toString()+ch)) {
				
				KsdlToken token = lexem.tokenize(currentRawToken.toString());

				tokens.add(token);
				currentRawToken.setLength(0);
				
				return true;
			}
		}
		
		return false;
	}
	
	private boolean checkWord(List<KsdlToken> tokens, StringBuilder currentRawToken, char ch) {
		
		for(KsdlLexem word : keyWords) {
			
			if(word.isMatch(currentRawToken) && ch == ' ') {
				
				KsdlToken token = word.tokenize(currentRawToken.toString());
				
				tokens.add(token);
				currentRawToken.setLength(0);

				return true;
			}			
		}
		
		return false;
	}
}
