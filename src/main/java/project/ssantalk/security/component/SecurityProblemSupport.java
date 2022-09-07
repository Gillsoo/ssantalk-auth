package project.ssantalk.security.component;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author dragon
 * @since 2021. 03. 15.
 */
@Slf4j
@Component
public class SecurityProblemSupport
									implements
										AuthenticationEntryPoint,
										AccessDeniedHandler {
	@Override
	public void commence(	final HttpServletRequest request,
							final HttpServletResponse response,
							final AuthenticationException exception) {
		try {
			response.sendError(	HttpServletResponse.SC_FORBIDDEN,
								exception.getMessage());
		}
		catch (IOException e) {
			log.error("",e);
		}
	}

	@Override
	public void handle(	final HttpServletRequest request,
						final HttpServletResponse response,
						final AccessDeniedException exception) {
		try {
			response.sendError(	HttpServletResponse.SC_NOT_ACCEPTABLE,
								   exception.getMessage());
		}
		catch (IOException e) {
			log.error("",e);
		}
	}
}
