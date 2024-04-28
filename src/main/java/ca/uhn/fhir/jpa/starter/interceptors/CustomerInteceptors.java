//package ca.uhn.fhir.jpa.starter.interceptors;
//
//import ca.uhn.fhir.i18n.Msg;
//import ca.uhn.fhir.interceptor.api.Hook;
//
//import ca.uhn.fhir.interceptor.api.Interceptor;
//import ca.uhn.fhir.interceptor.api.Pointcut;
//import ca.uhn.fhir.rest.api.server.RequestDetails;
//import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
//import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
//import org.springframework.security.oauth2.jwt.JwtValidators;
//import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
//import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
//
//@Interceptor
//public class CustomerInteceptors {
//	@Value("${spring.security.oauth2.resourceserver.opaque-token.introspection-uri}")
//	private String issuerToken;
//
//	@Value("${spring.security.oauth2.resourceserver.opaque-token.client-id}")
//	private String clientId;
//
//	@Value("${spring.security.oauth2.resourceserver.opaque-token.client-secret}")
//	private String clientSecret;
//
//	@Hook(Pointcut.SERVER_INCOMING_REQUEST_POST_PROCESSED)
//	public boolean incomingRequestPostProcessed(
//		RequestDetails requestDetails, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse)
//		throws AuthenticationException {
//
//		String authHeader = httpServletRequest.getHeader("Authorization");
//
//		if(authHeader == null || !authHeader.startsWith("bearer")){
//			throw new AuthenticationException(Msg.code(642) + "Missing or Invalid Authorization Header");
//		}
//
//		String accessToken = authHeader.replace("bearer ", "");
//
//		NimbusOpaqueTokenIntrospector nimbusOpaqueTokenIntrospector = new NimbusOpaqueTokenIntrospector(issuerToken, clientId, clientSecret);
//		OAuth2AuthenticatedPrincipal resultInpect = nimbusOpaqueTokenIntrospector.introspect(accessToken);
//		if (resultInpect != null){
//			return true;
//		}
//
//		return false;
//	}
//}
