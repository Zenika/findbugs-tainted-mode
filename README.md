findbugs-tainted-mode
=====================

The aim of this project is to write a detector for findbugs, that implements and performs taint analysis to find security vulnerabilities in Java code.

The code is based on TeachableSa project. OWASP Teachable Static Analysis Workbench Project has been developped in 2008 by Dmitry Kozlov and Igor Konnov.
TeachableSa contains a detector "secbugs" to use with findbugs and a plugin "Tesa" for eclipse. Tesa enables the user to mark the methods "sink" and "source" in the code to analyse, and transmits it to the detector.
Thus, the detector doesn't detect sink and source methods without Tesa.
The project hasn't been modified since 2009. 

Secbugs detector has been modified and improved to work by its own, with a list of source and sink methods. It can still work with tesa, and methods can be added using the plugin.
 
For now, the vulnerabilities detected are : 
	- SQL injection
	- command injection
	- cross site scripting
	- cookie poisoning
	- path traversal
	- HTTP splitting 
	
Input sources are 
	- command line parameters
	- environment variables
	- system properties
	- data retrieved from database
	- web requests (servlet, http)	


Building from source
--------------------

 - download eclipse (3.3 or later)
 - install Findbugs plugin : http://findbugs.cs.umd.edu/eclipse-daily/ (it has to be the daily release, otherwise it might not work)
 - import secbugs source project in Eclipse
 - run ant deploy-to-findbugs : it will compile sources and create secbugs.jar and secbugs_annotations.jar in "secbugs/dist" folder
 - make sure secbugs.jar is in the "plugin" folder of findbugs plugin install directory. if not copy it from "secbugs/dist"
 - restart eclipse
 - you can test on secbugs/test/cases/src/cases or run junit tests
 - to test on a project you need to add "secbugs_annotation.jar" to its libraries
