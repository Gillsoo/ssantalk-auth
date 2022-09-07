package project.ssantalk.security.component;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import project.ssantalk.security.UserMasterAuthentication;
import tools.orm.jpa.JpaAssistSpec;
import tools.orm.jpa.JpaAssistSpec.JpaSession;
import tools.orm.jpa.JpaAssistSpec.JpaSessionProvider;

import java.util.Optional;

/**
 * @author dragon
 * @since 2021. 04. 13.
 */
@Component
public class SecuritySessionProvider
										extends
		JpaSessionProvider {
	@Override
	public JpaSession getSession() {
		Authentication authentication = SecurityContextHolder	.getContext()
																.getAuthentication();
		return authentication != null && authentication instanceof UserMasterAuthentication ? (UserMasterAuthentication) authentication
																							: JpaAssistSpec.ANONYMOUS_SESSION;
	}

	public UserMasterAuthentication authentication() {
		return Optional	.ofNullable(SecurityContextHolder	.getContext()
															.getAuthentication())
						.filter(candidate -> candidate instanceof UserMasterAuthentication)
						.map(candidate -> (UserMasterAuthentication) candidate)
						.orElseThrow(() -> new RuntimeException("login info invalid"));
	}

	public Long getUserId() {
		return authentication()	.getTm()
								.getLoginId();
	}
}
