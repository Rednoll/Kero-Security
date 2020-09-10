package com.kero.security.lang.provider.resource;

public class CachedTextResource implements KsdlTextResource {
	
	private KsdlTextResource original;
	
	private String rawText;
	
	public CachedTextResource(KsdlTextResource original) {
	
		this.original = original;
	}
	
	@Override
	public String getRawText() {
		
		if(rawText == null) {
			
			rawText = original.getRawText();
		}
		
		return this.rawText;
	}
}
