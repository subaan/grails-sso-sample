package com.vmware.nee.saml

import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider
import org.opensaml.saml2.metadata.provider.MetadataProvider
import org.opensaml.xml.parse.BasicParserPool
import org.springframework.security.saml.metadata.ExtendedMetadata
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate

class IdpController {

	def metadata
	
    def index() {
		render view:"index"
	}
	
	def add(params){
		def filename = params?.file?.trim()
		if(filename){
			def file = new File(filename)
			FilesystemMetadataProvider provider = new FilesystemMetadataProvider(file)
			provider.setParserPool(new BasicParserPool())
			provider.initialize()
			MetadataProvider metadataProvider = new ExtendedMetadataDelegate(provider)
			metadata.addMetadataProvider(metadataProvider)
			metadata.setRefreshRequired(true)
			metadata.refreshMetadata()
		}
		redirect action: "list"
	}
	
	def remove(params){
		def entityName = params?.idp?.trim()
		if(entityName){
			metadata.providers.each{
				def name = metadata.parseProvider(it)[0] //if there is multiple entities in provider..This may not be right
				if(name == entityName) metadata.removeMetadataProvider(it)
				metadata.refreshMetadata()
			}
		}
		redirect action: "list"
	}
	
	def list(){
            def xml = new XmlParser().parse("./grails-app/conf/security/springSecuritySamlBeans1.xml")
            xml.'md:SPSSODescriptor'[0].'md:Extensions'.'idpdisco:DiscoveryResponse'.@'Location'[0].setValue("sdhdfuyfduddufidssf")
             xml.'md:SPSSODescriptor'.each { message ->
//                 println "tests-------------->  " + message
                 println "testssddsdsds-------------->  " + message.'md:Extensions'.'idpdisco:DiscoveryResponse'.@'Location'[0]
                 message.'md:Extensions'.'idpdisco:DiscoveryResponse'.@'Location'[0] = "https://sp123.authentication.com:8443/faas/login/auth/alias/faas?disco=true"
                 println "testssddsdsds-------------->  " + message.'md:SingleLogoutService'.@'Location'
                 message.'md:SingleLogoutService'.@'Location'.eachWithIndex  { location, i ->
                    println "loc" + i +": "+ location
                    message.'md:SingleLogoutService'.@'Location'[i] = "https://sp123.authentication.com:8443/faas/saml/SingleLogout/alias/faas"
                 }
                 println "testssddsdsds-------------->  " + message.'md:AssertionConsumerService'.@'Location'
                 message.'md:AssertionConsumerService'.@'Location'.eachWithIndex  { location, i ->
                    println "loc" + i +": "+ location
                    message.'md:AssertionConsumerService'.@'Location'[i] = "https://sp123.authentication.com:8443/faas/saml/SSO/alias/faas"
                }   
            }
  
            def stringWriter = new StringWriter()
            new XmlNodePrinter(new PrintWriter(stringWriter)).print(xml)
            def newXml = stringWriter.toString()
            println "<=========== newXml ===============>"
            println newXml
             
 
//            println "tests-------------->  " + xml
//            xml.each { xm ->
//                println "dffdf =========> "  + xm + "===========>"
//                println "tests-------------->  " + xm.SPSSODescriptor[0]
//                println "tests-------------->  " + xm.@SPSSODescriptor
//            }
		render view: "list"
	}
}
