package com.kero.security.core.utils;

import net.bytebuddy.description.type.TypeDescription;

public class ByteBuddyClassUtils {

	public static boolean checkAccessible(Class<?> target) {
		
		return TypeDescription.ForLoadedType.of(target).asErasure().isAccessibleTo(TypeDescription.ForLoadedType.of(ByteBuddyClassUtils.class));
	}
}
