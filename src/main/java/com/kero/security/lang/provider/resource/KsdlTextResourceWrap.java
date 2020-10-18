package com.kero.security.lang.provider.resource;

public interface KsdlTextResourceWrap extends KsdlTextResource {

	public default boolean hasWrap(Class<? extends KsdlTextResourceWrap> wrapClass) {
		
		if(wrapClass.isAssignableFrom(this.getClass())) return true;

		KsdlTextResource original = this.getOriginal();
		
		if(original instanceof KsdlTextResourceWrap) {
			
			return ((KsdlTextResourceWrap) original).hasWrap(wrapClass);
		}
		
		return false;
	}
	
	public KsdlTextResource getOriginal();
}
