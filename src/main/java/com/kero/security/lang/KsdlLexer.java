package com.kero.security.lang;

import java.util.LinkedList;
import java.util.List;

import com.kero.security.lang.lexems.DefaultRuleLexem;
import com.kero.security.lang.lexems.KeyWordLexem;
import com.kero.security.lang.lexems.KsdlLexem;
import com.kero.security.lang.lexems.NameLexem;
import com.kero.security.lang.lexems.RoleLexem;
import com.kero.security.lang.tokens.KeyWordToken;
import com.kero.security.lang.tokens.KsdlToken;

public class KsdlLexer {

	private List<KeyWordLexem> keyWords = new LinkedList<>();
	private List<KsdlLexem> lexems = new LinkedList<>();
	
	public KsdlLexer() {
	
		for(KeyWordLexem word : KeyWordLexem.values()) {
			
			keyWords.add(word);
		}
		
		lexems.add(new DefaultRuleLexem());
		lexems.add(new RoleLexem());
		lexems.add(new NameLexem());
	}
	
	public List<KsdlToken> tokenize(String data) {
		
		data += " ";
		data = data.replaceAll("\\r\\n", "\n");
		data = data.replaceAll("	", " ");
		data = data.replaceAll(" +", " ");
		
		System.out.println("data:" +data);
		
		boolean findShortEnd = false;
		
		LinkedList<KsdlToken> tokens = new LinkedList<>();

		StringBuilder currentRawToken = new StringBuilder();

		c2: for(char ch : data.toCharArray()) {
			
			boolean found = checkWord(tokens, currentRawToken, ch);
			
			if(found) {
				
				if(ch != ' ' && ch != '\n')
					currentRawToken.append(ch);
				continue c2;
			}
			
			checkLexem(tokens, currentRawToken, ch);

			if(ch != ' ' && ch != '\n')
				currentRawToken.append(ch);
		
			if(ch == ':') {
				
				findShortEnd = true;
			}
			
			if(ch == '\n' && findShortEnd) {
				
				tokens.add(KeyWordToken.CLOSE_BLOCK);
				findShortEnd = false;
			}
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
		
		for(KeyWordLexem word : keyWords) {
			
			if(word.isMatch(currentRawToken) && (!word.isRequireSpace() || (ch == ' ' || ch == '\n'))) {
				
				KsdlToken token = word.tokenize(currentRawToken.toString());
				
				tokens.add(token);
				currentRawToken.setLength(0);

				return true;
			}			
		}
		
		return false;
	}
}
