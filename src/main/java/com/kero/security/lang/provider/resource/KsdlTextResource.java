package com.kero.security.lang.provider.resource;

public interface KsdlTextResource {

	public String getRawText();
	
	public static KsdlTextResource addCacheWrap(KsdlTextResource resource) {
		
		if(resource instanceof KsdlTextResourceWrap) {
		
			KsdlTextResourceWrap wrap = (KsdlTextResourceWrap) resource;
			
			if(wrap.hasWrap(TextResourceCacheWrap.class)) {
				
				return wrap;
			}
		}
		
		return new TextResourceCacheWrap(resource);
	}
}
