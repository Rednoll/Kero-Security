package com.kero.security.lang.source;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class FileSource extends KsdlSourceBase {

	private String[] suffixes;
	private File file;
	
	public FileSource(File file, String... suffixes) {
	
		this.file = file;
		this.suffixes = suffixes;
	}
	
	@Override
	public String getRawText() {
		
		return collectText(this.file);
	}

	private String collectText(File src) {
		
		StringBuilder builder = new StringBuilder();
		 
		collectText(src, builder);
		
		return builder.toString();
	}
	
	private void collectText(File src, StringBuilder builder) {
		
		if(src.isFile()) {
			
			if(isSuitable(src)) {
				
				try {
					
					builder.append(new String(Files.readAllBytes(src.toPath())));
				}
				catch(IOException e) {
					
					throw new RuntimeException(e);
				}
			}
		}
		else if(src.isDirectory()) {
			
			for(File sub : src.listFiles()) {
				
				collectText(sub, builder);
			}
		}
	}
	
	private boolean isSuitable(File file) {
		
		for(String suffix : suffixes) {
		
			if(file.getName().endsWith(suffix)) {
				
				return true;
			}
		}
		
		return false;
	}
}
