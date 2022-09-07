package project.ssantalk.security;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import project.ssantalk.entity.struct.SessionMstrTM.LoginSessionTM;
import project.ssantalk.security.SecuritySpec.SecurityUserType;
import tools.orm.jpa.JpaAssistSpec.JpaSession;

import java.io.Serializable;
import java.util.Collection;

/**
 * @author dragon
 * @since 2021. 03. 14.
 */
@Data
@Slf4j
public class UserMasterAuthentication
										implements
											Authentication,
		JpaSession,
											Serializable {
	LoginSessionTM tm = null;

	SecurityUserType userType = null;

	public UserMasterAuthentication(LoginSessionTM tm) {
		super();
		this.tm = tm;
		this.userType = SecurityUserType.valueOf(tm.getLoginType());
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.userType.getAuthorities();
	}

	@Override
	public Object getDetails() {
		return tm;
	}

	@Override
	public Object getCredentials() {
		return tm.getToken();
	}

	@Override
	public Object getPrincipal() {
		return this;
	}

	@Override
	public boolean isAuthenticated() {
		return true;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		log.error(	"update authenticated?",
					new Throwable("TRACE"));
	}

	@Override
	public String getName() {
		return tm.getLoginName();
	}

	// ---------------------------------------------------------------------
	// Section jpa session implements
	// ---------------------------------------------------------------------

	@Override
	public String getUserId() {
		return tm	.getLoginId()
					.toString();
	}

	@Override
	public boolean isAnonymous() {
		return false;
	}

	@Override
	public Collection<String> getUserRoles() {
		return this.userType.getRoles();
	}
}
